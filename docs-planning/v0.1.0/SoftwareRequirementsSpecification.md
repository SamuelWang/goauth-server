# Software Requirements Specification - v0.1.0

## Introduction

### Purpose

At the initial version, the project infrastructure must be set up. Then, this system completes the Google Identity login flow.

### Scope

* Initializing project infrastructure  
* Google Identity login support

## Functional Requirements

### Authentication Module

#### Sign In

* The system shall allow users to sign in with Google Identity.

#### Sign Up

* The system shall create user profiles upon first login with Google Identity.

#### Session Management

* The system must issue a JWT access token in the cookie after successful login.

## Non-Functional Requirements

### Security

* The system must prevent CSRF attacks.
