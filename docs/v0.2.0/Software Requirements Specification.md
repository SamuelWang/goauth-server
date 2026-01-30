# Software Requirements Specification \- v0.2.0

## Introduction

### Purpose

This version of the SRS defines the requirements for enhancing the Google login flow, adding administrator capabilities, and implementing client and token management for the "Goauth" server.

### Scope

* Administrator Role and Permissions  
* Client Application Management (Registration, Update, Deletion)  
* oken and Code Management  
* Google Identity Login Flow Enhancements

## Functional Requirements

### Client Management Module

#### Client Management Operations (Admin)

* The system shall allow only authenticated administrators to register a new client application.  
* The client application shall be configured to exclusively use the OAuth 2.0 Authorization Code Grant flow.  
* The system shall allow only administrators to delete a registered client.  
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

### Authentication Module

#### Google Login Flow

* The Google login process shall exclusively support the Authorization Code Grant flow.  
* The system shall redirect the user to the configured callback URL with an authorization code. The client's server will then use this code to exchange for the actual access token.  
* The system shall validate that the requested callback URL for redirection matches a pre-registered callback URL for the client.

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

## Non-Functional Requirements

### Security

* The system must implement measures to prevent Cross-Site Request Forgery (CSRF) attacks.  
* The system must include protection against Cross-Site Scripting (XSS) and injection attacks (e.g., SQL injection).  
* The system shall support Cross-Origin Resource Sharing (CORS) as required for web-based clients.  
* The access token expiration shall not exceed 60 minutes.  
* The authorization code expiration shall not exceed 5 minutes.

#### Build and Deployment

* The system shall support deployment using Docker containers.
