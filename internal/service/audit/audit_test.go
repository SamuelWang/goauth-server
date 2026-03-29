package audit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mustMarshal is a test helper that marshals v to JSON and fails the test on error.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// --- Happy path: LogEvent calls CreateAuditLogEntry with correct params ---

func TestLogEvent_HappyPath(t *testing.T) {
	userID := uuid.New()
	clientID := uuid.New()
	actorID := uuid.New()
	ip := "192.0.2.1"
	metadata := map[string]any{"key": "value", "count": float64(1)}

	expectedParams := repository.CreateAuditLogEntryParams{
		EventType: string(EventLoginFailed),
		UserID:    userID,
		ClientID:  clientID,
		ActorID:   actorID,
		IpAddress: &ip,
		Metadata:  mustMarshal(t, metadata),
	}

	q := &mocks.MockQuerier{}
	q.On("CreateAuditLogEntry", mock.Anything, expectedParams).
		Return(uuid.New(), nil)

	svc := New(q)
	err := svc.LogEvent(context.Background(), AuditEntry{
		EventType: EventLoginFailed,
		UserID:    &userID,
		ClientID:  &clientID,
		ActorID:   &actorID,
		IPAddress: &ip,
		Metadata:  metadata,
	})

	require.NoError(t, err)
	q.AssertExpectations(t)
}

// --- DB error: returned error is propagated ---

func TestLogEvent_DBError(t *testing.T) {
	dbErr := errors.New("connection refused")

	q := &mocks.MockQuerier{}
	q.On("CreateAuditLogEntry", mock.Anything, mock.Anything).
		Return(uuid.UUID{}, dbErr)

	svc := New(q)
	err := svc.LogEvent(context.Background(), AuditEntry{
		EventType: EventAccountLocked,
		Metadata:  map[string]any{},
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, dbErr)
	q.AssertExpectations(t)
}

// --- Nil optional fields map to SQL zero-value UUID (zero UUID == NULL in pgx) ---

func TestLogEvent_NilOptionalFields(t *testing.T) {
	// When UserID, ClientID, ActorID and IPAddress are all nil, the params
	// should carry zero-value UUIDs and a nil IpAddress pointer.
	expectedParams := repository.CreateAuditLogEntryParams{
		EventType: string(EventDefaultAdminCreated),
		UserID:    uuid.UUID{}, // zero UUID — maps to NULL via pgx
		ClientID:  uuid.UUID{},
		ActorID:   uuid.UUID{},
		IpAddress: nil,
		Metadata:  mustMarshal(t, map[string]any{}),
	}

	q := &mocks.MockQuerier{}
	q.On("CreateAuditLogEntry", mock.Anything, expectedParams).
		Return(uuid.New(), nil)

	svc := New(q)
	err := svc.LogEvent(context.Background(), AuditEntry{
		EventType: EventDefaultAdminCreated,
		// UserID, ClientID, ActorID, IPAddress intentionally left nil
	})

	require.NoError(t, err)
	q.AssertExpectations(t)
}

// --- Empty Metadata marshals to {} not null ---

func TestLogEvent_EmptyMetadata_MarshalsToCurlyBraces(t *testing.T) {
	var capturedParams repository.CreateAuditLogEntryParams

	q := &mocks.MockQuerier{}
	q.On("CreateAuditLogEntry", mock.Anything, mock.AnythingOfType("repository.CreateAuditLogEntryParams")).
		Run(func(args mock.Arguments) {
			capturedParams = args.Get(1).(repository.CreateAuditLogEntryParams)
		}).
		Return(uuid.New(), nil)

	svc := New(q)

	// Explicit empty map
	err := svc.LogEvent(context.Background(), AuditEntry{
		EventType: EventAccountUnlocked,
		Metadata:  map[string]any{},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(capturedParams.Metadata))

	// Nil map — should also produce {}
	err = svc.LogEvent(context.Background(), AuditEntry{
		EventType: EventAccountUnlocked,
		Metadata:  nil,
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(capturedParams.Metadata))

	q.AssertExpectations(t)
}
