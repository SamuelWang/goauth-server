package audit

// EventType represents an audit log event type.
type EventType string

const (
	EventDefaultAdminCreated          EventType = "default_admin_created"
	EventDefaultClientCreated         EventType = "default_client_created"
	EventUserPasswordChanged          EventType = "user_password_changed"
	EventForcePasswordChangeSatisfied EventType = "force_password_change_satisfied"
	EventRefreshTokenIssued           EventType = "refresh_token_issued"
	EventRefreshTokenRotated          EventType = "refresh_token_rotated"
	EventRefreshTokenRevoked          EventType = "refresh_token_revoked"
	EventRefreshTokenFamilyRevoked    EventType = "refresh_token_family_revoked"
	EventReplayDetected               EventType = "replay_detected"
	EventAccessTokenRevoked           EventType = "access_token_revoked"
	EventAdminSessionRevoked          EventType = "admin_session_revoked"
	EventLoginFailed                  EventType = "login_failed"
	EventAccountLocked                EventType = "account_locked"
	EventAccountUnlocked              EventType = "account_unlocked"
	EventClientSecretRegenerated      EventType = "client_secret_regenerated"
)
