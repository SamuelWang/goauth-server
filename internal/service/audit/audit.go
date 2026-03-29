package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/google/uuid"
)

// AuditEntry holds the data for a single audit log event.
// Optional fields (UserID, ClientID, ActorID, IPAddress) may be nil.
// Metadata must never contain secrets; it is serialised to JSONB.
type AuditEntry struct {
	EventType EventType
	UserID    *uuid.UUID
	ClientID  *uuid.UUID
	ActorID   *uuid.UUID
	IPAddress *string
	Metadata  map[string]any
}

// Service writes audit log entries to the repository.
type Service struct {
	repo repository.Querier
}

// New returns a new audit Service backed by the given Querier.
func New(repo repository.Querier) *Service {
	return &Service{repo: repo}
}

// LogEvent persists an audit entry. If Metadata is nil it is stored as {}.
// Metadata marshalling failures are returned immediately without a DB call.
// DB errors are logged at WARN level and returned to the caller.
func (s *Service) LogEvent(ctx context.Context, entry AuditEntry) error {
	meta := entry.Metadata
	if meta == nil {
		meta = map[string]any{}
	}

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("audit: marshal metadata: %w", err)
	}

	params := repository.CreateAuditLogEntryParams{
		EventType: string(entry.EventType),
		IpAddress: entry.IPAddress,
		Metadata:  metaBytes,
	}
	if entry.UserID != nil {
		params.UserID = *entry.UserID
	}
	if entry.ClientID != nil {
		params.ClientID = *entry.ClientID
	}
	if entry.ActorID != nil {
		params.ActorID = *entry.ActorID
	}

	_, err = s.repo.CreateAuditLogEntry(ctx, params)
	if err != nil {
		slog.WarnContext(ctx, "audit: failed to write audit log entry",
			"event_type", string(entry.EventType),
			"error", err,
		)
		return err
	}

	return nil
}
