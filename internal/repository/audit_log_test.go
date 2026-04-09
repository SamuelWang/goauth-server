package repository

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuditLogEntry_AllOptionalFieldsNil(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	params := CreateAuditLogEntryParams{
		EventType: "login_failed",
		UserID:    uuid.Nil,
		ClientID:  uuid.Nil,
		ActorID:   uuid.Nil,
		IpAddress: nil,
		Metadata:  []byte("{}"),
	}

	id, err := queries.CreateAuditLogEntry(ctx, params)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, id)
}

func TestCreateAuditLogEntry_FullMetadataRoundTrip(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()
	user := createTestUser(t, queries, "auditlog")
	client := createTestClient(t, queries, "auditlog", user.ID)

	ip := "192.168.1.1"
	originalMeta := map[string]any{
		"email":      "user@example.com",
		"attempt":    float64(3),
		"source":     "web",
		"nested_key": map[string]any{"detail": "value"},
	}
	metaBytes, err := json.Marshal(originalMeta)
	require.NoError(t, err)

	params := CreateAuditLogEntryParams{
		EventType: "account_locked",
		UserID:    user.ID,
		ClientID:  client.ID,
		ActorID:   uuid.Nil,
		IpAddress: &ip,
		Metadata:  metaBytes,
	}

	id, err := queries.CreateAuditLogEntry(ctx, params)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, id)

	// Retrieve the entry from the list to verify metadata round-trip.
	// Filter by event_type, user_id, and client_id to scope to this test's data.
	entries, err := queries.ListAuditLogEntries(ctx, ListAuditLogEntriesParams{
		Column1: "account_locked",
		Column2: user.ID,
		Column3: client.ID,
		Limit:   10,
		Offset:  0,
	})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, id, entry.ID)
	assert.Equal(t, "account_locked", entry.EventType)
	assert.Equal(t, user.ID, entry.UserID)
	assert.Equal(t, client.ID, entry.ClientID)
	assert.Equal(t, ip, *entry.IpAddress)
	assert.NotZero(t, entry.CreatedAt)

	// Verify metadata JSON round-trip
	var roundTripped map[string]any
	err = json.Unmarshal(entry.Metadata, &roundTripped)
	require.NoError(t, err)
	assert.Equal(t, originalMeta["email"], roundTripped["email"])
	assert.Equal(t, originalMeta["attempt"], roundTripped["attempt"])
	assert.Equal(t, originalMeta["source"], roundTripped["source"])
	nested, ok := roundTripped["nested_key"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "value", nested["detail"])
}

func TestListAuditLogEntries_EventTypeFilter(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Create entries with two different event types, all with uuid.Nil user/client
	// so the zero-UUID filter matches them precisely.
	for range 3 {
		_, err := queries.CreateAuditLogEntry(ctx, CreateAuditLogEntryParams{
			EventType: "login_failed",
			UserID:    uuid.Nil,
			ClientID:  uuid.Nil,
			ActorID:   uuid.Nil,
			IpAddress: nil,
			Metadata:  []byte("{}"),
		})
		require.NoError(t, err)
	}

	for range 2 {
		_, err := queries.CreateAuditLogEntry(ctx, CreateAuditLogEntryParams{
			EventType: "account_locked",
			UserID:    uuid.Nil,
			ClientID:  uuid.Nil,
			ActorID:   uuid.Nil,
			IpAddress: nil,
			Metadata:  []byte("{}"),
		})
		require.NoError(t, err)
	}

	// Filter by "login_failed" only; Column2/Column3 = uuid.Nil matches
	// rows where user_id/client_id = zero UUID (our inserted rows).
	entries, err := queries.ListAuditLogEntries(ctx, ListAuditLogEntriesParams{
		Column1: "login_failed",
		Column2: uuid.Nil,
		Column3: uuid.Nil,
		Limit:   100,
		Offset:  0,
	})
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	for _, e := range entries {
		assert.Equal(t, "login_failed", e.EventType)
	}

	// Filter by "account_locked" returns only those 2 rows.
	entries, err = queries.ListAuditLogEntries(ctx, ListAuditLogEntriesParams{
		Column1: "account_locked",
		Column2: uuid.Nil,
		Column3: uuid.Nil,
		Limit:   100,
		Offset:  0,
	})
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	for _, e := range entries {
		assert.Equal(t, "account_locked", e.EventType)
	}
}

func TestCountAuditLogEntries_MatchesListTotal(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	const total = 5
	for range total {
		_, err := queries.CreateAuditLogEntry(ctx, CreateAuditLogEntryParams{
			EventType: "refresh_token_issued",
			UserID:    uuid.Nil,
			ClientID:  uuid.Nil,
			ActorID:   uuid.Nil,
			IpAddress: nil,
			Metadata:  []byte("{}"),
		})
		require.NoError(t, err)
	}

	filterParams := struct {
		Column1 string
		Column2 uuid.UUID
		Column3 uuid.UUID
	}{
		Column1: "refresh_token_issued",
		Column2: uuid.Nil,
		Column3: uuid.Nil,
	}

	count, err := queries.CountAuditLogEntries(ctx, CountAuditLogEntriesParams(filterParams))
	require.NoError(t, err)
	assert.Equal(t, int64(total), count)

	// List all entries with a high limit to retrieve the full set.
	entries, err := queries.ListAuditLogEntries(ctx, ListAuditLogEntriesParams{
		Column1: filterParams.Column1,
		Column2: filterParams.Column2,
		Column3: filterParams.Column3,
		Limit:   100,
		Offset:  0,
	})
	require.NoError(t, err)
	assert.Equal(t, int(count), len(entries))
}
