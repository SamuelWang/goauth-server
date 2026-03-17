# Software Requirements Specification - v0.3.0

## Introduction

### Purpose

This document specifies the software requirements for the GoAuth project, version 0.3.0. It defines the functional and non-functional requirements for the features being developed in this release, including default administrator account creation, default client bootstrap, and support for refresh tokens in the authorization code grant flow.

### Scope

* Default Administrator Account Creation
* Default Client Bootstrap
* Authorization Code Grant with Refresh Tokens
* Client Manual for Frontend Integration

## Functional Requirements

### Default Administrator Account

- The system MUST support creating a default administrator account at startup when no administrator exists.
- The default administrator credentials MUST be supplied via environment variables named `DEFAULT_ADMIN_USERNAME` and `DEFAULT_ADMIN_PASSWORD`.
- If both `DEFAULT_ADMIN_USERNAME` and `DEFAULT_ADMIN_PASSWORD` are present and there is no existing administrator user, the system MUST create an administrator user with the supplied username and password during application startup.
- The system MUST NOT store the plaintext default password. The password MUST be hashed using the application's standard password hashing mechanism before persisting to the database.
- The system MUST force a password change on first login for an account created from default credentials and MUST log the event (audit entry) for compliance.
- Using default admin credentials MUST be restricted for production deployments. By default production mode MUST ignore these environment variables unless an explicit opt-in variable `ALLOW_DEFAULT_ADMIN=true` is set. The system SHOULD emit a clear warning in logs when a default admin account is created.
- If the provided credentials fail validation (e.g., username empty, password fails complexity requirements), application startup MUST fail with a descriptive error message.
- The system MUST provide a documented procedure for revoking and rotating the default administrator credentials (for example, deleting the created user, forcing password change, or setting the variables to empty and restarting).
- The environment variables and their security implications MUST be documented in the project documentation and deployment guides.

**Environment variable examples**

- `DEFAULT_ADMIN_USERNAME=admin`
- `DEFAULT_ADMIN_PASSWORD=ChangeMeNow!`
- `ALLOW_DEFAULT_ADMIN=false` (default; set to `true` to allow creation in production)

**Security notes**

- Default-admin creation is intended for initial setup and testing only. Operators MUST rotate or remove the default account immediately after first use.
- The application MUST hash passwords and never persist plaintext values from environment variables.
- The default-admin feature MUST be accompanied by audit logging and monitored usage.

### Default Client Bootstrap

- The system MUST support creating a default OAuth client at startup when no clients exist.
- The default client credentials and metadata MUST be supplied via environment variables named `DEFAULT_CLIENT_ID`, `DEFAULT_CLIENT_SECRET`, and `DEFAULT_CLIENT_REDIRECT_URIS` (comma-separated). Optional metadata MAY be supplied via `DEFAULT_CLIENT_NAME` and `DEFAULT_CLIENT_CONFIDENTIAL` (true/false).
- If `DEFAULT_CLIENT_ID` and `DEFAULT_CLIENT_SECRET` are present and there is no existing client, the system MUST create the client during application startup.
- The system MUST NOT store plaintext default client secrets. Secrets MUST be stored using the application's standard secret storage mechanism and MUST NOT be emitted in logs or audit trails that expose secrets.
- For confidential clients, the system MUST force rotation of the default client secret on first use and MUST log creation and first-use events for audit/compliance.
- Default-client creation MUST be disabled by default in production mode. Production MUST ignore these environment variables unless an explicit opt-in `ALLOW_DEFAULT_CLIENT=true` is set. The system SHOULD emit a clear warning in logs when a default client is created.
- If provided client metadata fails validation (for example, invalid redirect URIs), application startup MUST fail with a descriptive error message.
- The system MUST provide a documented procedure for revoking and rotating the default client (for example, deleting the created client, rotating secrets, or unsetting the variables and restarting).
- The environment variables and their security implications MUST be documented in the project documentation and deployment guides.

**Environment variable examples**

- `DEFAULT_CLIENT_ID=goauth`
- `DEFAULT_CLIENT_SECRET=ChangeMeNow!`
- `DEFAULT_CLIENT_REDIRECT_URIS=https://localhost:3001/cb`
- `DEFAULT_CLIENT_NAME=GoAuth Client`
- `ALLOW_DEFAULT_CLIENT=false` (default; set to `true` to allow creation in production)

**Security notes**

- Default-client creation is intended for initial setup and testing only. Operators MUST rotate or remove default clients immediately after first use.
- The application MUST protect client secrets and never persist plaintext values from environment variables.
- Default-client creation MUST be accompanied by audit logging, monitoring, and documented rotation procedures.

### Authorization Code Grant — Refresh Tokens

- The system MUST issue refresh tokens when using the OAuth 2.0 Authorization Code Grant to support long-lived sign-in sessions where the client requests an `offline_access` scope or equivalent.
- Refresh tokens MUST only be issued to clients that are allowed to receive them (for example, confidential clients) unless explicitly permitted for public clients by configuration.
- Refresh tokens MUST be stored securely (for example, hashed or encrypted) and MUST NOT be emitted in logs, audit trails, or other outputs that could expose secrets.
- The system MUST support configurable refresh-token lifetime and rotation policies. When rotation is enabled, each successful use of a refresh token MUST issue a new refresh token and invalidate the previous one.
- The system MUST detect reuse of a rotated refresh token (replay) and, on detection, revoke all active tokens associated with the session and log an audit event describing the incident (without including token material).
- The system MUST provide a token revocation endpoint compatible with RFC 7009 that allows clients or operators to revoke refresh tokens and associated access tokens immediately. Revocation requests MUST be authenticated as required by the OAuth specification.
- Refresh tokens MUST be bound to the issuing client and SHOULD be bound to additional context (for example device identifiers or session identifiers) when practical to reduce token theft impact.
- The system MUST revoke or rotate refresh tokens on sensitive events such as user password changes, administrator-initiated session invalidation, or explicit user logout.
- Refresh-token issuance, rotation, revocation, and replay-detection events MUST be audited in logs and monitoring systems; audit entries MUST NOT contain token secrets or other sensitive token material.
- By default, production deployments MUST not allow creation of long-lived refresh tokens from default bootstrap flows unless an explicit opt-in configuration (for example `ALLOW_DEFAULT_CLIENT_REFRESH=true`) is set; the system SHOULD emit a clear warning when such tokens are created.
- The system MUST document the refresh-token behaviour, operator procedures for revocation and rotation, and security implications for deployments.

## Non-Functional Requirements

### Security

- **Password and secret handling:** All passwords and client secrets MUST be hashed or encrypted using the application's standard secure mechanisms (for example, Argon2/Bcrypt for passwords and a KMS/encryption-at-rest mechanism for client secrets). Secrets MUST never be logged or included in audit messages.
- **Transport security:** All network traffic carrying credentials, tokens, or other sensitive information MUST be protected by TLS (HTTPS) in production.
- **Default-credential protections:** Environment-driven default account/client bootstrap features MUST be disabled by default in production and require an explicit opt-in (`ALLOW_DEFAULT_ADMIN`, `ALLOW_DEFAULT_CLIENT`, etc.). Creation of default credentials MUST emit a high-visibility warning in logs and an audit entry (without secret material).
- **Audit logging:** Security-relevant events (account creation, default bootstrap, refresh-token issuance/rotation/revocation, detected replay, admin actions) MUST be logged to an append-only audit log. Audit entries MUST NOT contain secrets or token values.

### Performance

- **Authentication latency:** Typical end-to-end authentication and token issuance flows SHOULD complete within 200ms under normal load for a single instance (excluding network latency to clients). Password hashing/verification cost SHOULD be tuned to balance security and latency.
- **Throughput:** The service MUST be horizontally scalable to support increased request rates via additional instances and load balancing. The system SHOULD support connection pooling for database access to maintain predictable throughput.

### Reliability & Availability

- **Availability target:** The service SHOULD be architected to meet a 99.9% uptime SLA for production deployments when deployed with recommended redundancy.
- **Statelessness:** Server instances SHOULD be stateless where practical; session and token state MUST be persisted in a durable store (database or token store) so instances can be scaled and restarted without user impact.
- **Failover and upgrades:** Migrations and rolling upgrades MUST preserve token state and avoid downtime for active sessions where possible.

### Scalability

- **Horizontal scaling:** The application MUST allow adding instances behind a load balancer; token and session data MUST remain consistent across instances.
- **Database scaling:** The design MUST permit standard DB scaling strategies (read replicas, connection pooling, partitioning) and document limitations for production loads.

### Observability & Monitoring

- **Metrics:** Expose Prometheus-compatible metrics for request rates, latencies, token issuance/rotation/revocation counts, failed authentication attempts, and DB connection usage.
- **Tracing:** Support distributed tracing (OpenTelemetry) for end-to-end debugging of request/token flows.
- **Alerting:** Provide clear operational alerting thresholds for error rates, auth-failure spikes, and replay-detection incidents.

### Maintainability & Supportability

- **Code quality:** Modules MUST be unit-tested, and critical flows (login, token exchange, refresh, revocation) MUST have integration tests.
- **Documentation:** Operator and developer documentation MUST include deployment guidance, environment variable descriptions, rollback procedures, and security guidance for default-credential features.

### Compliance & Audit

- **Retention and privacy:** Audit logs and token-alike metadata retention periods MUST be configurable; sensible defaults SHOULD be provided (for example, 90 days for audit logs), and privacy implications documented.
- **Revocation & forensics:** The system MUST provide sufficient logging and revocation capabilities to support incident response without exposing secrets.

### Operational Requirements

- **Migrations:** Database migrations MUST be backward-compatible where possible and well-tested in staging prior to production runs.
- **Backups:** Operators MUST perform regular backups of persistent stores containing authorization/state data and validate restore procedures.
- **Kubernetes readiness/liveness:** Containerized deployments SHOULD include health checks, readiness probes, and graceful shutdown handling to support rolling upgrades.

### Testing and Validation

- **Functional tests:** Automated tests MUST validate default admin/client bootstrap behavior, refresh token rotation and replay detection, and revocation endpoints.
- **Security testing:** Static analysis, dependency scanning, and periodic penetration testing or vulnerability scans SHOULD be part of release validation for production deployments.
- **Load testing:** Documented load and spike test scenarios SHOULD be executed before production rollouts that target high throughput.

## Acceptance Criteria

- **Default admin creation:** When `DEFAULT_ADMIN_USERNAME` and `DEFAULT_ADMIN_PASSWORD` are provided and no admin exists, the application creates an admin account at startup (with `ALLOW_DEFAULT_ADMIN` semantics applied). The stored password is hashed and the user is marked to require password change on first login. An audit entry is created (without the password).
- **Default client creation:** When `DEFAULT_CLIENT_ID` and `DEFAULT_CLIENT_SECRET` are provided and no client exists, the application creates the client at startup (with `ALLOW_DEFAULT_CLIENT` semantics applied). The stored client secret is not logged in cleartext, and creation is audited.
- **Refresh token issuance and rotation:** The authorization code flow issues refresh tokens for eligible clients; when rotation is enabled, using a refresh token invalidates the previous token and issues a new one. Reuse of an invalidated refresh token triggers immediate revocation of related tokens and writes an audit event describing the incident.
- **Revocation endpoint:** The token revocation endpoint accepts authenticated revocation requests per RFC 7009 and causes immediate invalidation of the target token(s).
- **Config validation:** If bootstrap environment variables fail validation (empty username, invalid redirect URIs, weak password), application startup fails with a descriptive error.

## Traceability

- **Functional → Implementation:** Requirements in the Functional Requirements section map directly to API behaviors, database schema changes (see `db/migrations`), and service-layer implementations found under `internal/service` and `internal/repository`.
- **Acceptance tests:** Each acceptance criterion above MUST have corresponding automated tests in the integration test suite (see `internal/testutil` and `internal/loadtest`).

## Glossary

- **Confidential client:** An OAuth client capable of maintaining client credentials confidentially (typically server-side applications).
- **Public client:** An OAuth client that cannot keep credentials secret (for example, single-page applications, mobile apps).
- **Refresh token rotation:** The security pattern where a refresh token is replaced with a new one on each use, and previous tokens are invalidated.

## Notes and Operator Guidance

- Document the security implications of environment-driven bootstrap features prominently in operator guides and deployment manifests (see `docs/AdministratorGuide.md` and `k8s/` manifests). Operators SHOULD rotate or remove default credentials immediately after initial setup.

## Manual Document Requirement (GoAuth client - Frontend)

- **Purpose:** The project MUST provide a consumer-facing manual targeted at frontend developers integrating the GoAuth client (the "client manual"). The manual is intended to be the canonical guide for installing, configuring, and integrating the frontend with the GoAuth server.
- **Location:** The manual SHOULD live in the repository under `docs/ClientManual.md` and be surfaced via project documentation indexes.
- **Scope (minimum):** The client manual MUST include:
	- Local development setup and build instructions for common frontend frameworks (example: React).
	- Configuration and required environment variables for local and production use.
	- OAuth flows used by the client (authorization code, PKCE, refresh token usage) with sequence diagrams or step-by-step examples.
	- Redirect URI configuration and validation guidance.
	- Secure handling of tokens on the client (storage recommendations, token rotation handling, and when refresh tokens are appropriate).
	- Integration examples and snippets for signing in, token exchange, refresh, and revocation.
	- Troubleshooting and common errors (CORS, redirect issues, invalid_grant, replay detection symptoms).
	- Instructions for rotating secrets and revoking tokens from the client perspective.
	- Testing guidance (unit and integration tests, local mocks, and end-to-end scenarios).
	- Security considerations and recommended secure defaults for SPA and server-side rendered clients.
- **Maintenance:** The manual MUST be updated whenever client-facing APIs or OAuth behavior change. Release checklists and PR templates SHOULD include a reminder to review and update the client manual as needed.
