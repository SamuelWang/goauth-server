// Package loadtest_test contains performance load tests that verify the
// v0.2.0 API meets the <200 ms p95 latency SLA under concurrent load.
//
// The tests run against an in-process [httptest.Server] backed by a mock
// repository (no real database), measuring pure application-layer latency:
// routing, middleware pipeline, business logic, and JSON serialisation.
//
// Skipped automatically when the -short flag is passed so they do not block
// the normal unit-test CI step. Run directly with:
//
//	go test ./internal/loadtest/ -v -run TestLoad -timeout 120s
package loadtest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/SamuelWang/goauth-server/internal/config"
	"github.com/SamuelWang/goauth-server/internal/middleware"
	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/service/audit"
	authsvc "github.com/SamuelWang/goauth-server/internal/service/auth"
	clientsvc "github.com/SamuelWang/goauth-server/internal/service/client"
	providersvc "github.com/SamuelWang/goauth-server/internal/service/provider"
	sessionsvc "github.com/SamuelWang/goauth-server/internal/service/session"
	usersvc "github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	v1 "github.com/SamuelWang/goauth-server/internal/transport/http/api/v1"
	v1handler "github.com/SamuelWang/goauth-server/internal/transport/http/api/v1/handler"
	"github.com/SamuelWang/goauth-server/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Load test constants
// ---------------------------------------------------------------------------

const (
	// loadConcurrency is the number of concurrent goroutines per scenario.
	loadConcurrency = 25

	// loadReqsPerWorker is the number of sequential requests each worker sends
	// during the timed measurement window.
	loadReqsPerWorker = 40

	// loadWarmupReqs is the number of un-timed requests fired before measurement
	// to prime in-process data structures and loopback TCP connections.
	loadWarmupReqs = 20

	// p95SLAMs is the v0.2.0 success-criteria target: 95th-percentile response
	// time must be strictly less than this value (milliseconds).
	p95SLAMs = 200
)

// ---------------------------------------------------------------------------
// Environment setup
// ---------------------------------------------------------------------------

// loadEnv holds the in-process test server and pre-generated credentials.
type loadEnv struct {
	cfg      *config.Config
	mockQ    *mocks.MockQuerier
	server   *httptest.Server
	client   *http.Client
	authSvc  *authsvc.Service
	auditSvc *audit.Service
	privKey  *ecdsa.PrivateKey
}

// newLoadEnv constructs an in-process httptest.Server backed by a mock
// repository. The router configuration mirrors the production setup minus
// the Prometheus /metrics endpoint (which requires a running registry).
func newLoadEnv(t *testing.T) *loadEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// Generate a fresh ECDSA P-256 key pair for JWT signing.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalECPrivateKey(privKey)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	cfg := &config.Config{
		App:    config.AppConfig{Name: "load-test"},
		Server: config.ServerConfig{Env: "development", Scheme: "http", HostName: "localhost", Port: "8080"},
		AccessToken: config.AccessTokenConfig{
			PrivateKey: privPEM,
			PublicKey:  pubPEM,
			Expiry:     60,
		},
	}

	mockQ := &mocks.MockQuerier{}

	// provider service must be created before auth service.
	encKey := make([]byte, 32)
	_, err = rand.Read(encKey)
	require.NoError(t, err)
	pSvc, err := providersvc.New(mockQ, encKey, cfg.Server.Env)
	require.NoError(t, err)

	auditSvc := audit.New(mockQ)

	as, err := authsvc.New(mockQ, cfg, pSvc, auditSvc)
	require.NoError(t, err)

	uSvc := usersvc.New(mockQ)
	cSvc := clientsvc.New(mockQ, cfg.Server.Env, auditSvc)
	sSvc := sessionsvc.New(mockQ)

	router := gin.New()
	router.Use(middleware.MaxBodySizeMiddleware())
	router.Use(middleware.SecurityHeadersMiddleware(cfg.Server.Env))

	// In-line health-check route (mirrors ops handler).
	router.GET("/ops/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// API v1 routes (auth, clients, providers, users, sessions).
	apiV1 := router.Group("/api/v1")
	apiV1.Use(middleware.ContextMiddleware(cfg))
	v1.RegisterRoutes(apiV1, as, uSvc, pSvc, cSvc, sSvc, auditSvc)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &loadEnv{
		cfg:      cfg,
		mockQ:    mockQ,
		server:   srv,
		client:   srv.Client(),
		authSvc:  as,
		auditSvc: auditSvc,
		privKey:  privKey,
	}
}

// ---------------------------------------------------------------------------
// Load runner
// ---------------------------------------------------------------------------

// loadResult collects timing samples for a single scenario.
type loadResult struct {
	scenario  string
	latencies []time.Duration
	errors    int
}

// percentile returns the Pth percentile latency (P in [0,100]).
func (r *loadResult) percentile(p float64) time.Duration {
	if len(r.latencies) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(r.latencies))
	copy(sorted, r.latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * p / 100.0)
	return sorted[idx]
}

func (r *loadResult) maxLatency() time.Duration {
	if len(r.latencies) == 0 {
		return 0
	}
	m := r.latencies[0]
	for _, d := range r.latencies[1:] {
		if d > m {
			m = d
		}
	}
	return m
}

// runScenario dispatches loadConcurrency goroutines, each sending
// loadReqsPerWorker requests sequentially, and returns collected results.
// A warmup phase (not recorded) fires first to stabilise latency.
func runScenario(
	t *testing.T,
	client *http.Client,
	name string,
	wantStatus int,
	newReq func() *http.Request,
) *loadResult {
	t.Helper()

	// Warmup.
	for i := 0; i < loadWarmupReqs; i++ {
		resp, err := client.Do(newReq())
		if err == nil {
			resp.Body.Close()
		}
	}

	type sample struct {
		d   time.Duration
		err bool
	}
	ch := make(chan sample, loadConcurrency*loadReqsPerWorker)

	var wg sync.WaitGroup
	for w := 0; w < loadConcurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < loadReqsPerWorker; i++ {
				req := newReq()
				start := time.Now()
				resp, err := client.Do(req)
				d := time.Since(start)
				if err != nil {
					ch <- sample{d: d, err: true}
					continue
				}
				resp.Body.Close()
				ch <- sample{d: d, err: resp.StatusCode != wantStatus}
			}
		}()
	}
	wg.Wait()
	close(ch)

	res := &loadResult{scenario: name}
	for s := range ch {
		if s.err {
			res.errors++
		} else {
			res.latencies = append(res.latencies, s.d)
		}
	}
	return res
}

// ---------------------------------------------------------------------------
// Flow scenario runner
// ---------------------------------------------------------------------------

// runFlowScenario is like runScenario but designed for multi-step VU flows.
// flow() performs all steps sequentially and returns true on full success.
// The wall-clock time of each complete VU flow is recorded as one latency sample.
func runFlowScenario(
	t *testing.T,
	_ *http.Client, // kept for signature consistency
	name string,
	flow func() bool,
) *loadResult {
	t.Helper()

	// Warmup (un-timed).
	for i := 0; i < loadWarmupReqs; i++ {
		flow()
	}

	type sample struct {
		d   time.Duration
		err bool
	}
	ch := make(chan sample, loadConcurrency*loadReqsPerWorker)

	var wg sync.WaitGroup
	for w := 0; w < loadConcurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < loadReqsPerWorker; i++ {
				start := time.Now()
				ok := flow()
				d := time.Since(start)
				ch <- sample{d: d, err: !ok}
			}
		}()
	}
	wg.Wait()
	close(ch)

	res := &loadResult{scenario: name}
	for s := range ch {
		if s.err {
			res.errors++
		} else {
			res.latencies = append(res.latencies, s.d)
		}
	}
	return res
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

// TestLoad runs four representative load scenarios and asserts that the
// p95 latency is under the 200 ms SLA target for each.
//
//   - Scenario 1 – GET /ops/health: no auth, no DB, baseline overhead only.
//   - Scenario 2 – GET /api/v1/clients/:id/auth/providers: public endpoint,
//     one mock DB call (list enabled providers).
//   - Scenario 3 – GET /api/v1/auth/me: authenticated endpoint; JWT
//     validation + revocation check + user lookup (two mock DB calls).
//   - Scenario 4 – Refresh token lifecycle: exchange auth code → access+refresh
//     tokens, rotate the refresh token 3×, revoke the final refresh token.
func TestLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load tests in -short mode")
	}

	env := newLoadEnv(t)
	base := env.server.URL

	// -----------------------------------------------------------------------
	// Scenario 2: list enabled providers (one mock DB call per request).
	// -----------------------------------------------------------------------
	clientID := uuid.New()
	env.mockQ.
		On("ListEnabledOAuthProvidersByClient", mock.Anything, clientID).
		Return([]repository.OauthProvider{
			buildProvider(uuid.New(), clientID, "google"),
			buildProvider(uuid.New(), clientID, "github"),
		}, nil).
		Maybe()

	// -----------------------------------------------------------------------
	// Scenario 3: GET /api/v1/auth/me (two mock DB calls per request).
	// -----------------------------------------------------------------------
	userID := uuid.New()
	rawToken, err := env.authSvc.GenerateAccessToken(userID.String(), "loadtest@example.com")
	require.NoError(t, err)

	tHash := util.SHA256Hex(rawToken)
	notRevoked := false
	tokenRow := repository.AccessToken{
		ID:        uuid.New(),
		TokenHash: tHash,
		UserID:    userID,
		ClientID:  func() *uuid.UUID { id := uuid.New(); return &id }(),
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &notRevoked,
	}
	env.mockQ.
		On("GetAccessToken", mock.Anything, tHash).
		Return(tokenRow, nil).
		Maybe()

	isAdmin := false
	isActive := true
	userRow := repository.User{
		ID:            userID,
		Email:         "loadtest@example.com",
		EmailVerified: true,
		IsActive:      isActive,
		IsAdmin:       &isAdmin,
		Locale:        "en-US",
		LastLoginAt:   time.Now(),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	env.mockQ.
		On("GetUserByID", mock.Anything, userID).
		Return(userRow, nil).
		Maybe()

	// -----------------------------------------------------------------------
	// Scenario 4: Refresh Token Lifecycle.
	// Client with AllowRefreshTokens=true exchanges an auth code for an
	// access+refresh token pair, rotates the refresh token three times, and
	// finally revokes it via POST /api/v1/auth/revoke (RFC 7009).
	// -----------------------------------------------------------------------
	rtClientID := uuid.New()
	const rtClientSecret = "lt-rt-load-test-secret"
	rtSecretHash := util.SHA256Hex(rtClientSecret)
	rtIsActive := true
	rtClient := repository.Client{
		ID:                 rtClientID,
		Name:               "Load Test RT Client",
		ClientSecretHash:   rtSecretHash,
		RedirectUris:       []string{"http://localhost:3000/callback"},
		GrantTypes:         []string{"authorization_code", "refresh_token"},
		IsActive:           &rtIsActive,
		AllowRefreshTokens: true,
		IsConfidential:     true,
	}

	const rtAuthCode = "lt-rt-fixed-auth-code"
	rtScopeStr := "openid email offline_access"
	rtCodeID := uuid.New()
	rtCodeRevoked := false
	rtAuthCodeRec := repository.AuthorizationCode{
		ID:          rtCodeID,
		Code:        rtAuthCode,
		ClientID:    rtClientID,
		UserID:      userID,
		ExpiresAt:   time.Now().Add(30 * time.Minute),
		RedirectUri: "http://localhost:3000/callback",
		Scope:       &rtScopeStr,
		IsRevoked:   &rtCodeRevoked,
	}

	rtAtID := uuid.New()
	rtAtRevoked := false
	rtAtRec := repository.AccessToken{
		ID:        rtAtID,
		TokenHash: "lt-rt-at-hash",
		ClientID:  &rtClientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
		IsRevoked: &rtAtRevoked,
	}
	rtRec := repository.RefreshToken{
		ID:            uuid.New(),
		TokenFamilyID: uuid.New(),
		TokenHash:     "lt-rt-rt-hash",
		ClientID:      rtClientID,
		UserID:        userID,
		AccessTokenID: rtAtID,
		Scope:         rtScopeStr,
		ExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
		IsRevoked:     false,
	}

	env.mockQ.On("GetClient", mock.Anything, rtClientID).Return(rtClient, nil).Maybe()
	env.mockQ.On("GetAuthorizationCode", mock.Anything, rtAuthCode).Return(rtAuthCodeRec, nil).Maybe()
	env.mockQ.On("MarkAuthorizationCodeUsed", mock.Anything, rtCodeID).Return(rtAuthCodeRec, nil).Maybe()
	env.mockQ.On("CreateAccessToken", mock.Anything, mock.Anything).Return(rtAtRec, nil).Maybe()
	env.mockQ.On("CreateRefreshToken", mock.Anything, mock.Anything).Return(rtRec, nil).Maybe()
	env.mockQ.On("CreateAuditLogEntry", mock.Anything, mock.Anything).Return(uuid.New(), nil).Maybe()
	env.mockQ.On("GetRefreshTokenByHash", mock.Anything, mock.Anything).Return(rtRec, nil).Maybe()
	env.mockQ.On("MarkRefreshTokenUsed", mock.Anything, mock.Anything).Return(nil).Maybe()
	env.mockQ.On("RevokeRefreshToken", mock.Anything, mock.Anything).Return(nil).Maybe()
	env.mockQ.On("GetAccessTokenByID", mock.Anything, rtAtID).Return(rtAtRec, nil).Maybe()
	env.mockQ.On("RevokeAccessToken", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Build a dedicated httptest.Server for the RT lifecycle scenario.
	// The token/revoke endpoints on the main server carry a 10 req/min/IP
	// rate limit that would make the load scenario artificially fail at scale.
	// This minimal router omits per-IP rate limiting so we measure pure
	// handler + service-layer latency, consistent with the other scenarios.
	rtGin := gin.New()
	rtGin.Use(middleware.MaxBodySizeMiddleware())
	rtGin.Use(middleware.SecurityHeadersMiddleware("development"))
	rtApiV1 := rtGin.Group("/api/v1")
	rtApiV1.Use(middleware.ContextMiddleware(env.cfg))
	rtH := v1handler.New(env.authSvc, nil, nil, nil, nil, env.auditSvc)
	rtApiV1.POST("/auth/token", rtH.TokenExchange)
	rtApiV1.POST("/auth/revoke", rtH.Revoke)
	rtSrv := httptest.NewServer(rtGin)
	t.Cleanup(rtSrv.Close)
	rtSrvClient := rtSrv.Client()
	rtBase := rtSrv.URL

	// rtFlow is the multi-step VU for scenario 4.  All steps must succeed for
	// the iteration to be counted as a successful latency sample.
	rtFlow := func() bool {
		// Step 1: Exchange the fixed auth code for an access + refresh token.
		step1Body, _ := json.Marshal(map[string]string{
			"grant_type":    "authorization_code",
			"code":          rtAuthCode,
			"client_id":     rtClientID.String(),
			"client_secret": rtClientSecret,
			"redirect_uri":  "http://localhost:3000/callback",
		})
		req1, _ := http.NewRequest(http.MethodPost, rtBase+"/api/v1/auth/token", bytes.NewReader(step1Body))
		req1.Header.Set("Content-Type", "application/json")
		resp1, err := rtSrvClient.Do(req1)
		if err != nil || resp1.StatusCode != http.StatusOK {
			if resp1 != nil {
				resp1.Body.Close()
			}
			return false
		}
		var tok1 struct {
			RefreshToken string `json:"refresh_token"`
		}
		json.NewDecoder(resp1.Body).Decode(&tok1) //nolint:errcheck
		resp1.Body.Close()
		currentRT := tok1.RefreshToken
		if currentRT == "" {
			return false
		}

		// Step 2: Rotate the refresh token three times.
		for i := 0; i < 3; i++ {
			rotBody, _ := json.Marshal(map[string]string{
				"grant_type":    "refresh_token",
				"refresh_token": currentRT,
				"client_id":     rtClientID.String(),
				"client_secret": rtClientSecret,
			})
			rotReq, _ := http.NewRequest(http.MethodPost, rtBase+"/api/v1/auth/token", bytes.NewReader(rotBody))
			rotReq.Header.Set("Content-Type", "application/json")
			rotResp, err := rtSrvClient.Do(rotReq)
			if err != nil || rotResp.StatusCode != http.StatusOK {
				if rotResp != nil {
					rotResp.Body.Close()
				}
				return false
			}
			var rotTok struct {
				RefreshToken string `json:"refresh_token"`
			}
			json.NewDecoder(rotResp.Body).Decode(&rotTok) //nolint:errcheck
			rotResp.Body.Close()
			currentRT = rotTok.RefreshToken
			if currentRT == "" {
				return false
			}
		}

		// Step 3: Revoke the final refresh token.
		formValues := url.Values{
			"token":           {currentRT},
			"token_type_hint": {"refresh_token"},
		}
		revokeReq, _ := http.NewRequest(http.MethodPost, rtBase+"/api/v1/auth/revoke",
			strings.NewReader(formValues.Encode()))
		revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		revokeReq.SetBasicAuth(rtClientID.String(), rtClientSecret)
		revokeResp, err := rtSrvClient.Do(revokeReq)
		if err != nil || revokeResp.StatusCode != http.StatusOK {
			if revokeResp != nil {
				revokeResp.Body.Close()
			}
			return false
		}
		revokeResp.Body.Close()
		return true
	}

	// -----------------------------------------------------------------------
	// Run all four scenarios.
	// -----------------------------------------------------------------------
	results := []*loadResult{
		runScenario(t, env.client, "GET /ops/health", http.StatusOK,
			func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, base+"/ops/health", nil)
				return req
			},
		),
		runScenario(t, env.client, "GET /api/v1/clients/:id/auth/providers", http.StatusOK,
			func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet,
					base+"/api/v1/clients/"+clientID.String()+"/auth/providers", nil)
				return req
			},
		),
		runScenario(t, env.client, "GET /api/v1/auth/me", http.StatusOK,
			func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/auth/me", nil)
				req.Header.Set("Authorization", "Bearer "+rawToken)
				return req
			},
		),
		runFlowScenario(t, env.client, "RT lifecycle (code→tokens, rotate×3, revoke)", rtFlow),
	}

	// -----------------------------------------------------------------------
	// Print results table.
	// -----------------------------------------------------------------------
	totalReqs := loadConcurrency * loadReqsPerWorker
	fmt.Fprintf(os.Stdout, "\n=== Load test results (concurrency=%d, reqs/worker=%d, total=%d) ===\n\n",
		loadConcurrency, loadReqsPerWorker, totalReqs)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Scenario\tReqs\tErrors\tp50\tp95\tp99\tMax")
	fmt.Fprintln(w, "--------\t----\t------\t---\t---\t---\t---")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\t%s\t%s\n",
			r.scenario,
			len(r.latencies)+r.errors,
			r.errors,
			fmtDur(r.percentile(50)),
			fmtDur(r.percentile(95)),
			fmtDur(r.percentile(99)),
			fmtDur(r.maxLatency()),
		)
	}
	w.Flush()
	fmt.Println()

	// -----------------------------------------------------------------------
	// Assert SLA.
	// -----------------------------------------------------------------------
	failed := false
	for _, r := range results {
		if r.errors > 0 {
			t.Errorf("scenario %q: %d request(s) returned unexpected status", r.scenario, r.errors)
			failed = true
		}
		p95 := r.percentile(95)
		if p95 >= time.Duration(p95SLAMs)*time.Millisecond {
			t.Errorf("scenario %q: p95 latency %s exceeds %d ms SLA",
				r.scenario, fmtDur(p95), p95SLAMs)
			failed = true
		}
	}
	if !failed {
		fmt.Fprintf(os.Stdout, "✓ All scenarios satisfy p95 < %d ms SLA\n\n", p95SLAMs)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fmtDur(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fµs", float64(d.Microseconds()))
	}
	return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000.0)
}

func buildProvider(id, clientID uuid.UUID, name string) repository.OauthProvider {
	enabled := true
	return repository.OauthProvider{
		ID:          id,
		ClientID:    clientID,
		Name:        name,
		DisplayName: name + " Display",
		Scopes:      []string{"openid", "email"},
		IsEnabled:   &enabled,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}
