package repository

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var testDB *pgxpool.Pool
var postgresContainer *postgres.PostgresContainer

func TestMain(m *testing.M) {
	ctx := context.Background()

	// Start PostgreSQL container
	var err error
	postgresContainer, err = postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("goauth_test"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2),
		),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed to start postgres container: %v\n", err)
		fmt.Fprintln(os.Stderr, "\nMake sure Docker is running and you have permission to access it.")
		fmt.Fprintln(os.Stderr, "You may need to add your user to the docker group:")
		fmt.Fprintln(os.Stderr, "  sudo usermod -aG docker $USER")
		fmt.Fprintln(os.Stderr, "  newgrp docker")
		os.Exit(1)
	}

	// Get connection string
	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		panic("failed to get connection string: " + err.Error())
	}

	// Create connection pool
	testDB, err = pgxpool.New(ctx, connStr)
	if err != nil {
		panic("failed to connect to test database: " + err.Error())
	}

	// Run migrations
	if err := runMigrations(ctx, testDB); err != nil {
		testDB.Close()
		postgresContainer.Terminate(ctx)
		panic("failed to run migrations: " + err.Error())
	}

	// Run tests
	code := m.Run()

	// Cleanup
	testDB.Close()
	if err := postgresContainer.Terminate(ctx); err != nil {
		fmt.Printf("failed to terminate container: %s\n", err)
	}

	os.Exit(code)
}

// runMigrations runs all database migrations in order
func runMigrations(ctx context.Context, db *pgxpool.Pool) error {
	// Navigate up from internal/repository to the project root
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	migrationsPath := filepath.Join(wd, "..", "..", "db", "migrations")

	// Run all migrations in chronological order
	migrationFiles := []string{
		"20260109145607_create_users_table.up.sql",
		"20260213095938_add_is_admin_to_users.up.sql",
		"20260213100111_create_clients_table.up.sql",
		"20260216155147_create_oauth_providers_table.up.sql",
		"20260216155730_create_authorization_codes_table.up.sql",
		"20260301120000_create_access_tokens_table.up.sql",
		"20260326090601_add_lockout_force_password_to_users.up.sql",
		"20260326092318_add_confidential_refresh_tokens_to_clients.up.sql",
		"20260326092900_create_refresh_tokens_table.up.sql",
		"20260326093100_create_audit_log_table.up.sql",
	}

	for _, file := range migrationFiles {
		migrationSQL, err := os.ReadFile(filepath.Join(migrationsPath, file))
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file, err)
		}

		if _, err = db.Exec(ctx, string(migrationSQL)); err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", file, err)
		}
	}

	return nil
}

func setupTest(t *testing.T) (*Queries, func()) {
	t.Helper()

	tx, err := testDB.Begin(context.Background())
	require.NoError(t, err)

	queries := New(tx)

	cleanup := func() {
		tx.Rollback(context.Background())
	}

	return queries, cleanup
}
