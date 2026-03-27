-- Create audit_log table migration (UP)
-- Append-only table for security-relevant events.
-- No secrets or token values are written to this table.

CREATE TABLE audit_log (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  TEXT        NOT NULL,
    user_id     UUID,
    client_id   UUID,
    actor_id    UUID,
    ip_address  TEXT,
    metadata    JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for filtering by event type
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);

-- Index for user-scoped audit queries
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);

-- Index for client-scoped audit queries
CREATE INDEX idx_audit_log_client_id ON audit_log(client_id);

-- Index for time-range filtering and retention queries
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
