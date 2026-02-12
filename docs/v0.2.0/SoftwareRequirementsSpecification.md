# Software Requirements Specification - v0.2.0

## Introduction

### Purpose

This version of the SRS defines the requirements for implementing a client-scoped OAuth provider architecture, enhancing OAuth login flows, adding administrator capabilities, and implementing client, provider, and token management for the "Goauth" server.

### Scope

* Administrator Role and Permissions  
* Client Application Management (Registration, Update, Deletion)  
* OAuth Provider Management (Client-Scoped, Multi-Provider Support)
* Token and Code Management
* OAuth 2.0 Authorization Code Grant Flow with Configurable Providers

## Functional Requirements

### Client Management Module

#### Client Management Operations (Admin)

* The system shall allow only authenticated administrators to register a new client application.  
* The client application shall be configured to exclusively use the OAuth 2.0 Authorization Code Grant flow.  
* Each client application shall be able to configure multiple OAuth providers independently.
* The system shall allow only administrators to delete a registered client.  
* When a client is deleted, all associated OAuth providers shall be automatically removed (cascading delete).
* The system shall allow only administrators to update a client's details, including basic data and secret key regeneration.  
* The server shall provide the necessary RESTful APIs to facilitate all client management operations on the administrator's web interface.  
  * List clients  
  * Get a client  
  * Patch a client  
  * Regenerate the secret of a client  
  * Delete a client

### User Module

#### Administrator Flag

* The user data model shall include a boolean flag to designate a user as an administrator.

#### User Management (Admin)

* The system shall provide the necessary APIs for user management functionalities available on the admin website.  
  * List users  
  * Disable a user

### OAuth Provider Management Module

#### Client-Scoped Provider Architecture

* Each OAuth provider shall belong to exactly one client application.
* A client application may have zero or more OAuth providers configured.
* OAuth providers shall be completely isolated between clients - one client cannot access or use another client's providers.
* The same provider type (e.g., "google", "github", "microsoft") may be configured independently by multiple clients with different credentials and settings.
* The system shall enforce a unique constraint on provider name within each client scope (client_id, name).

#### OAuth Provider Management Operations (Admin)

* The system shall allow only authenticated administrators to create OAuth providers for a client application.
* The system shall allow only administrators to update a client's OAuth provider configuration.
* The system shall allow only administrators to delete a client's OAuth provider.
* The system shall allow administrators to enable or disable specific providers for a client.
* Provider credentials (client ID and client secret for the OAuth provider) shall be encrypted before storage.
* Provider credentials shall never be returned in API responses.
* The server shall provide the necessary RESTful APIs to facilitate all OAuth provider management operations:  
  * List providers for a client  
  * Get a specific provider (with ownership validation)
  * Create a provider for a client  
  * Update a provider (with ownership validation)
  * Delete a provider (with ownership validation)
  * Enable/disable a provider

#### Supported OAuth Provider Types

* The system shall support configurable OAuth 2.0 providers with the following parameters:
  * Provider name (e.g., "google", "github", "microsoft")
  * Display name for user interface
  * Provider client ID (credentials from the OAuth provider)
  * Provider client secret (credentials from the OAuth provider)
  * Authorization URL
  * Token URL
  * User info URL
  * Requested scopes
  * Enabled/disabled status

### Authentication Module

#### OAuth Authorization Code Grant Flow

* The authentication process shall exclusively support the OAuth 2.0 Authorization Code Grant flow.
* The system shall allow users to select from enabled OAuth providers configured for the requesting client.
* The system shall validate that the requested OAuth provider exists, is enabled, and belongs to the requesting client.
* The system shall redirect the user to the selected provider's authorization URL.
* The system shall handle the OAuth provider callback and exchange the authorization code for user information.
* The system shall redirect the user to the configured callback URL with an authorization code. The client's server will then use this code to exchange for the actual access token.
* The system shall validate that the requested callback URL for redirection matches a pre-registered callback URL for the client.
* The system shall verify that authorization codes are only exchanged by the client that initiated the flow.

### Session Management Module

#### Token Tracking

* The system must persistently track every issued access token within the database for auditing and revocation purposes.

#### Code Tracking

* The system must track the issued authorization code when a client uses the Authorization Code Grant flow.

#### Session Management (Admin)

* The system shall provide the necessary APIs for session and token management on the administrator's web interface.  
  * List codes  
  * List access tokens  
  * Delete a code  
  * Delete an access token
* Authorization codes and access tokens shall be associated with the OAuth provider used for authentication.

## Non-Functional Requirements

### Security

* The system must implement measures to prevent Cross-Site Request Forgery (CSRF) attacks.  
* The system must include protection against Cross-Site Scripting (XSS) and injection attacks (e.g., SQL injection).  
* The system shall support Cross-Origin Resource Sharing (CORS) as required for web-based clients.  
* The access token expiration shall not exceed 60 minutes.  
* The authorization code expiration shall not exceed 5 minutes.
* OAuth provider credentials shall be encrypted at rest using AES-256-GCM or equivalent.
* The system shall enforce client ownership validation for all provider operations to prevent cross-client provider access.
* The system shall validate OAuth provider callbacks to ensure they originated from legitimate OAuth providers.

### Performance and Scalability

* The system shall support multiple clients with isolated provider configurations without performance degradation.
* Provider configuration lookups shall be optimized with appropriate database indexing on (client_id, name) and (client_id, is_enabled).

### Data Isolation

* The system shall ensure complete data isolation between clients' OAuth provider configurations.
* No client shall be able to view, modify, or use OAuth providers belonging to another client.
* Database foreign key constraints shall enforce cascading deletion of providers when a client is deleted.

#### Build and Deployment

* The system shall support deployment using Docker containers.
