# AGENTS.md

This document provides instructions for AI agents working on the `goauth-server` project.

## Project Overview

`goauth-server` is a Golang service for an authentication platform. Key technologies include Golang, Gin, PostgreSQL, and `sqlc`.

Refer to the `README.md` file for detailed setup and usage instructions.

## Commands

Here are the common commands for this project.

### Setup

- **Install Dependencies:**
  ```bash
  go mod download
  ```

### Database

- **Run Migrations:**
  ```bash
  ./scripts/db/run_migrations.sh
  ```

- **Create a New Migration:**
  ```bash
  migrate create -ext sql -dir ./internal/db/migrations <migration_name>
  ```

- **Rollback Migrations:**
  ```bash
  ./scripts/db/rollback_migrations.sh [N]
  ```

- **Generate SQL code from queries:**
  ```bash
  sqlc generate
  ```

### Application

- **Run the Application:**
  ```bash
  go run ./cmd/auth-service
  ```

## File Structure

- `cmd/auth-service`: Main application entry point.
- `internal/app/auth-service/`: Application setup and initialization.
- `internal/db/`: Database-related code and queries.
- `internal/db/migrations/`: Database migration files.
- `internal/db/queries/`: SQL query files for sqlc.
- `internal/db/schema/`: Database schema dumps.
- `internal/handler/`: HTTP request handlers.
- `internal/middleware/`: HTTP middleware components.
- `internal/repository/`: Data access layer that the code is generated from sqlc queries.
- `internal/service/`: Business logic layer.
- `scripts/db/`: Database migration and schema management scripts.

## Code Style and Conventions

- **Style:** Follow the existing code style. Pay attention to formatting, naming conventions, and comments in the surrounding code.
- **Go:** Adhere to standard Go idioms.
- **SQL:** Use the formatting provided by `Prettier SQL VSCode`.

## Boundaries

- **Always:**
  - Follow the instructions in this document.
  - Run `sqlc generate` after modifying files in `internal/db/queries/`.
  - Add migrations when changing the database schema.
- **Ask First:**
  - Before making significant changes to the architecture.
  - Before adding new dependencies.
- **Never:**
  - Commit secrets or credentials to the repository.
  - Modify the `.gitignore` file without permission.
