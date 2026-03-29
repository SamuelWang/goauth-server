package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newTestService(q *mocks.MockQuerier) *Service {
	return New(q, "development", nil)
}

// sampleClientSecret is the plain-text secret whose SHA-256 hash is stored in
// sampleClient. Tests that exercise secret validation should use this value.
const sampleClientSecret = "test-client-secret"

func sampleClient() repository.Client {
	isActive := true
	return repository.Client{
		ID:               uuid.New(),
		Name:             "test-client",
		ClientSecretHash: hashSecret(sampleClientSecret),
		RedirectUris:     []string{"https://example.com/callback"},
		GrantTypes:       []string{"authorization_code"},
		IsActive:         &isActive,
		CreatedBy:        uuid.New(),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

// --- ListClients ---

func TestListClients_DefaultsToActive(t *testing.T) {
	row := sampleClient()
	q := &mocks.MockQuerier{}
	q.On("ListClients", mock.Anything, repository.ListClientsParams{
		Column1: true,
		Limit:   20,
		Offset:  0,
	}).Return([]repository.Client{row}, nil)
	q.On("CountClients", mock.Anything, true).Return(int64(1), nil)

	svc := newTestService(q)
	result, err := svc.ListClients(context.Background(), ListClientsParams{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.Total)
	require.Len(t, result.Clients, 1)
	assert.Equal(t, row.ID, result.Clients[0].ID)
	q.AssertExpectations(t)
}

func TestListClients_RepoError(t *testing.T) {
	q := &mocks.MockQuerier{}
	q.On("ListClients", mock.Anything, mock.Anything).Return(nil, errors.New("db down"))

	svc := newTestService(q)
	_, err := svc.ListClients(context.Background(), ListClientsParams{})
	require.Error(t, err)
	q.AssertExpectations(t)
}

// --- GetClient ---

func TestGetClient_Found(t *testing.T) {
	row := sampleClient()
	q := &mocks.MockQuerier{}
	q.On("GetClient", mock.Anything, row.ID).Return(row, nil)

	svc := newTestService(q)
	c, err := svc.GetClient(context.Background(), row.ID)
	require.NoError(t, err)
	assert.Equal(t, row.ID, c.ID)
	assert.Equal(t, row.Name, c.Name)
	q.AssertExpectations(t)
}

func TestGetClient_NotFound(t *testing.T) {
	id := uuid.New()
	q := &mocks.MockQuerier{}
	q.On("GetClient", mock.Anything, id).Return(repository.Client{}, pgx.ErrNoRows)

	svc := newTestService(q)
	_, err := svc.GetClient(context.Background(), id)
	assert.ErrorIs(t, err, ErrClientNotFound)
	q.AssertExpectations(t)
}

// --- CreateClient ---

func TestCreateClient_Success(t *testing.T) {
	adminID := uuid.New()
	row := sampleClient()
	dto := CreateClientDTO{
		Name:         "new-client",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		IsActive:     true,
	}

	q := &mocks.MockQuerier{}
	q.On("CreateClient", mock.Anything, mock.MatchedBy(func(p repository.CreateClientParams) bool {
		return p.Name == dto.Name && p.CreatedBy == adminID && p.ClientSecretHash != ""
	})).Return(row, nil)

	svc := newTestService(q)
	result, err := svc.CreateClient(context.Background(), dto, adminID)
	require.NoError(t, err)
	assert.NotEmpty(t, result.PlainSecret)
	assert.Equal(t, row.ID, result.ID)
	q.AssertExpectations(t)
}

func TestCreateClient_DuplicateName(t *testing.T) {
	adminID := uuid.New()
	dto := CreateClientDTO{
		Name:         "existing",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	}

	q := &mocks.MockQuerier{}
	pgErr := &pgconn.PgError{Code: "23505"}
	q.On("CreateClient", mock.Anything, mock.Anything).Return(repository.Client{}, pgErr)

	svc := newTestService(q)
	_, err := svc.CreateClient(context.Background(), dto, adminID)
	assert.ErrorIs(t, err, ErrDuplicateClientName)
	q.AssertExpectations(t)
}

func TestCreateClient_ValidationError_MissingName(t *testing.T) {
	dto := CreateClientDTO{
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	}
	svc := newTestService(&mocks.MockQuerier{})
	_, err := svc.CreateClient(context.Background(), dto, uuid.New())
	require.Error(t, err)
	var ve *ValidationError
	assert.True(t, errors.As(err, &ve))
	assert.Equal(t, "name", ve.Field)
}

func TestCreateClient_ValidationError_InvalidRedirectURI(t *testing.T) {
	dto := CreateClientDTO{
		Name:         "client",
		RedirectURIs: []string{"not-a-url"},
		GrantTypes:   []string{"authorization_code"},
	}
	svc := newTestService(&mocks.MockQuerier{})
	_, err := svc.CreateClient(context.Background(), dto, uuid.New())
	require.Error(t, err)
	var ve *ValidationError
	assert.True(t, errors.As(err, &ve))
	assert.Equal(t, "redirect_uris", ve.Field)
}

func TestCreateClient_ValidationError_UnsupportedGrantType(t *testing.T) {
	dto := CreateClientDTO{
		Name:         "client",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"implicit"},
	}
	svc := newTestService(&mocks.MockQuerier{})
	_, err := svc.CreateClient(context.Background(), dto, uuid.New())
	require.Error(t, err)
	var ve *ValidationError
	assert.True(t, errors.As(err, &ve))
	assert.Equal(t, "grant_types", ve.Field)
}

// --- UpdateClient ---

func TestUpdateClient_Success(t *testing.T) {
	row := sampleClient()
	dto := UpdateClientDTO{
		Name:         "updated-name",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	}

	updated := row
	updated.Name = dto.Name
	q := &mocks.MockQuerier{}
	q.On("UpdateClient", mock.Anything, repository.UpdateClientParams{
		ID:           row.ID,
		Name:         dto.Name,
		Description:  nil,
		RedirectUris: dto.RedirectURIs,
		GrantTypes:   dto.GrantTypes,
	}).Return(updated, nil)

	svc := newTestService(q)
	c, err := svc.UpdateClient(context.Background(), row.ID, dto)
	require.NoError(t, err)
	assert.Equal(t, "updated-name", c.Name)
	q.AssertExpectations(t)
}

func TestUpdateClient_NotFound(t *testing.T) {
	id := uuid.New()
	dto := UpdateClientDTO{
		Name:         "name",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	}
	q := &mocks.MockQuerier{}
	q.On("UpdateClient", mock.Anything, mock.Anything).Return(repository.Client{}, pgx.ErrNoRows)

	svc := newTestService(q)
	_, err := svc.UpdateClient(context.Background(), id, dto)
	assert.ErrorIs(t, err, ErrClientNotFound)
	q.AssertExpectations(t)
}

func TestUpdateClient_DuplicateName(t *testing.T) {
	id := uuid.New()
	dto := UpdateClientDTO{
		Name:         "taken-name",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	}
	q := &mocks.MockQuerier{}
	pgErr := &pgconn.PgError{Code: "23505"}
	q.On("UpdateClient", mock.Anything, mock.Anything).Return(repository.Client{}, pgErr)

	svc := newTestService(q)
	_, err := svc.UpdateClient(context.Background(), id, dto)
	assert.ErrorIs(t, err, ErrDuplicateClientName)
	q.AssertExpectations(t)
}

// --- RegenerateSecret ---

func TestRegenerateSecret_Success(t *testing.T) {
	row := sampleClient()
	q := &mocks.MockQuerier{}
	q.On("GetClient", mock.Anything, row.ID).Return(row, nil)
	q.On("RegenerateClientSecret", mock.Anything, mock.MatchedBy(func(p repository.RegenerateClientSecretParams) bool {
		return p.ID == row.ID && p.ClientSecretHash != ""
	})).Return(row, nil)

	svc := newTestService(q)
	result, err := svc.RegenerateSecret(context.Background(), row.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, result.PlainSecret)
	q.AssertExpectations(t)
}

func TestRegenerateSecret_NotFound(t *testing.T) {
	id := uuid.New()
	q := &mocks.MockQuerier{}
	q.On("GetClient", mock.Anything, id).Return(repository.Client{}, pgx.ErrNoRows)

	svc := newTestService(q)
	_, err := svc.RegenerateSecret(context.Background(), id)
	assert.ErrorIs(t, err, ErrClientNotFound)
	q.AssertExpectations(t)
}

// --- DeleteClient ---

func TestDeleteClient_Success(t *testing.T) {
	row := sampleClient()
	q := &mocks.MockQuerier{}
	q.On("GetClient", mock.Anything, row.ID).Return(row, nil)
	q.On("DeleteClient", mock.Anything, row.ID).Return(nil)

	svc := newTestService(q)
	err := svc.DeleteClient(context.Background(), row.ID)
	require.NoError(t, err)
	q.AssertExpectations(t)
}

func TestDeleteClient_NotFound(t *testing.T) {
	id := uuid.New()
	q := &mocks.MockQuerier{}
	q.On("GetClient", mock.Anything, id).Return(repository.Client{}, pgx.ErrNoRows)

	svc := newTestService(q)
	err := svc.DeleteClient(context.Background(), id)
	assert.ErrorIs(t, err, ErrClientNotFound)
	q.AssertExpectations(t)
}

// --- Secret generation ---

func TestGenerateSecret_IsBase64URL(t *testing.T) {
	secret, err := generateSecret()
	require.NoError(t, err)
	// 32 bytes base64url-encoded without padding = 43 chars
	assert.Len(t, secret, 43)
}

func TestHashSecret_MatchesPlain(t *testing.T) {
	plain := "my-secret"
	hash := hashSecret(plain)
	assert.NotEmpty(t, hash)
	// SHA-256 hex digest is always 64 characters
	assert.Len(t, hash, 64)
	// Deterministic: same input always yields the same hash
	assert.Equal(t, hash, hashSecret(plain))
}

// --- ValidateClientSecret ---

func TestValidateClientSecret_Match(t *testing.T) {
	plain := "super-secret-value"
	stored := hashSecret(plain)
	assert.True(t, ValidateClientSecret(stored, plain))
}

func TestValidateClientSecret_Mismatch(t *testing.T) {
	stored := hashSecret("correct-secret")
	assert.False(t, ValidateClientSecret(stored, "wrong-secret"))
}

// --- Validation errors ---

func TestClientValidationError_ErrorString(t *testing.T) {
	ve := &ValidationError{Field: "name", Message: "required"}
	assert.Equal(t, "name: required", ve.Error())
}

func TestUpdateClient_ValidationErrors(t *testing.T) {
	base := UpdateClientDTO{
		Name:         "valid-name",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	}

	cases := []struct {
		name  string
		patch func(*UpdateClientDTO)
		field string
	}{
		{"missing name", func(d *UpdateClientDTO) { d.Name = "" }, "name"},
		{"empty redirect_uris", func(d *UpdateClientDTO) { d.RedirectURIs = nil }, "redirect_uris"},
		{"invalid redirect_uri", func(d *UpdateClientDTO) { d.RedirectURIs = []string{"not-a-url"} }, "redirect_uris"},
		{"empty grant_types", func(d *UpdateClientDTO) { d.GrantTypes = nil }, "grant_types"},
		{"unsupported grant_type", func(d *UpdateClientDTO) { d.GrantTypes = []string{"implicit"} }, "grant_types"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dto := base
			tc.patch(&dto)
			svc := newTestService(&mocks.MockQuerier{})
			_, err := svc.UpdateClient(context.Background(), uuid.New(), dto)
			require.Error(t, err)
			var ve *ValidationError
			require.True(t, errors.As(err, &ve))
			assert.Equal(t, tc.field, ve.Field)
		})
	}
}

func TestCreateClient_ValidationError_ProductionHTTPS(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := New(q, "production", nil)
	dto := CreateClientDTO{
		Name:         "prod-app",
		RedirectURIs: []string{"http://external.example.com/callback"}, // http in production (non-loopback)
		GrantTypes:   []string{"authorization_code"},
	}
	_, err := svc.CreateClient(context.Background(), dto, uuid.New())
	require.Error(t, err)
	var ve *ValidationError
	require.True(t, errors.As(err, &ve))
	assert.Equal(t, "redirect_uris", ve.Field)
}

func TestCreateClient_ValidationError_BadScheme(t *testing.T) {
	q := &mocks.MockQuerier{}
	svc := newTestService(q)
	dto := CreateClientDTO{
		Name:         "test-app",
		RedirectURIs: []string{"ftp://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	}
	_, err := svc.CreateClient(context.Background(), dto, uuid.New())
	require.Error(t, err)
	var ve *ValidationError
	require.True(t, errors.As(err, &ve))
	assert.Equal(t, "redirect_uris", ve.Field)
}

// --- Additional Get/Delete/Regenerate error paths ---

func TestGetClient_RepoError(t *testing.T) {
	id := uuid.New()
	q := &mocks.MockQuerier{}
	q.On("GetClient", mock.Anything, id).Return(repository.Client{}, errors.New("db error"))

	svc := newTestService(q)
	_, err := svc.GetClient(context.Background(), id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "getting client")
}

func TestRegenerateSecret_RepoUpdateError(t *testing.T) {
	row := sampleClient()
	q := &mocks.MockQuerier{}
	q.On("GetClient", mock.Anything, row.ID).Return(row, nil)
	q.On("RegenerateClientSecret", mock.Anything, mock.Anything).Return(repository.Client{}, errors.New("db error"))

	svc := newTestService(q)
	_, err := svc.RegenerateSecret(context.Background(), row.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "updating client secret")
}

func TestDeleteClient_RepoDeleteError(t *testing.T) {
	row := sampleClient()
	q := &mocks.MockQuerier{}
	q.On("GetClient", mock.Anything, row.ID).Return(row, nil)
	q.On("DeleteClient", mock.Anything, row.ID).Return(errors.New("db error"))

	svc := newTestService(q)
	err := svc.DeleteClient(context.Background(), row.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deleting client")
}

func TestListClients_CountError(t *testing.T) {
	q := &mocks.MockQuerier{}
	isActive := true
	q.On("ListClients", mock.Anything, mock.Anything).Return([]repository.Client{}, nil)
	q.On("CountClients", mock.Anything, isActive).Return(int64(0), errors.New("db error"))

	svc := newTestService(q)
	_, err := svc.ListClients(context.Background(), ListClientsParams{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "counting clients")
}
