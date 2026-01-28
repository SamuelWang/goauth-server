# Software Requirements Specification - v0.2.0

## Introduction

### Purpose

This version shall enhance the completeness of the Google login flow, add administrator permissions, and support client and token management.

The system shall support client management. The administrators can register clients. The clients can use 

When using the Google login flow to directly get the access token (the access token flow), the client can bring its client

In addition to the direct login flow with the access token, the system supports the code exchange flow. The code exchange flow allows the client to meet the cross-domain requirements.

### Scope

* Administrator permission  
* Client management  
* Token management  
* Google login flow

## Functional Requirements

### Client Module

#### Registration

* The system shall be able to register a client. Only administrators can do client registration.  
* Every client can decide which login flow to use (access token in cookie or code exchange flow)

#### Management

* The system shall support the client's deletion. Only administrators can delete a client.  
* The system shall support the client’s update. Only administrators can update a client.

### Authentication Module

#### Administrator

* The user data shall include a flag indicating whether a user is an administrator.

#### Sign In

* The client can ask the system to redirect users back to a callback URL. The callback URL must match the registered callback URL.  
* The system shall support the code exchange login flow for Google login. The users shall be redirected to the callback with a code. The client uses the code to exchange the real access token.

### Session Management

#### Token Management

* The system must track every issued access token in the database.

#### Code Management

* When a client uses the code exchange login flow, the system must track the issued code.

## Non-Functional Requirements

### Security

* The system must prevent CSRF attacks.  
* Protection against XSS (Cross-Site Scripting) and injection attacks.  
* The system shall support CORS.  
* The expiration of access tokens must be 60 minutes.  
* The expiration of the exchange code must be 5 minutes.

#### Build and Deployment

* The system shall support the Docker container deployment.