# goauth-server

A Golang service of the auth platform.

## Setup Instructions

1. **Clone the Repository**

   ```bash
   git clone https://github.com/SamuelWang/goauth-server.git
   cd goauth-server
   ```

2. **Install Dependencies**

   Ensure you have Go installed. Then, run:

   ```bash
   go mod download
   ```

3. **Set Up the Database**

   Make sure you have PostgreSQL installed and running. Create a new database for the application.

4. **Configure Environment Variables**

   Create a `.env` file in the root directory by copying the `.env.example` and set the necessary environment variables (e.g., database connection string, server port).

5. **Run Database Migrations**

   Use `golang-migrate` to run the migrations:

   ```bash
   chmod +x scripts/db/run_migrations.sh
   ./scripts/db/run_migrations.sh
   ```

6. **Run the Application**

   Start the auth service:

   ```bash
   go run ./cmd/auth-service
   ```

## Database Migrations

Database migration scripts are located in the `scripts/db/migrations` directory. If you need to add new migrations, ensure you have `golang-migrate` installed.

### New Migrations

Follow the instructions below to create and apply new migrations:

1. Create a new migration:

   ```bash
   migrate create -ext sql -dir ./scripts/db/migrations -seq <migration_name>
   ```

2. Apply migrations to the database:

   ```bash
   chmod +x scripts/db/run_migrations.sh
   ./scripts/db/run_migrations.sh [N]
   ```

3. Dump the database schema:

   ```bash
   chmod +x scripts/db/dump_schema.sh
   ./scripts/db/dump_schema.sh
   ```

4. Write SQL queries in the appropriate files under `internal/db/queries/`.

5. Generate SQL code with sqlc:

   ```bash
   sqlc generate
   ```

### Rollback Migrations

If you need to rollback migrations the repository provides a helper script. Usage:

```bash
chmod +x scripts/db/rollback_migrations.sh
# rollback all migrations (default)
./scripts/db/rollback_migrations.sh
# rollback N down migrations (e.g. 2)
./scripts/db/rollback_migrations.sh 2
```

## Development

### Technologies Used

- Golang
- Gin Web Framework
- PostgreSQL
- sqlc + pgx
- golang-migrate

### Recommended IDE Setup

For development, it's recommended to use Visual Studio Code with the following extensions:

- [Go](https://marketplace.visualstudio.com/items?itemName=golang.Go)
- [Prettier SQL VSCode](https://marketplace.visualstudio.com/items?itemName=inferrinizzard.prettier-sql-vscode)

### File Structure

- `cmd/auth-service`: Main application entry point.
- `internal/db`: Database-related code and queries.
- `scripts/db`: Database migration and schema management scripts.
