package repository

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
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
	// Get the project root directory
	// Navigate up from internal/repository to the project root
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Go up two levels from internal/repository to project root
	projectRoot := filepath.Join(wd, "..", "..")
	migrationsPath := filepath.Join(projectRoot, "db", "migrations")

	// Run all migrations in chronological order
	migrationFiles := []string{
		"20260109145607_create_users_table.up.sql",
		"20260213095938_add_is_admin_to_users.up.sql",
		"20260213100111_create_clients_table.up.sql",
		"20260216155147_create_oauth_providers_table.up.sql",
		"20260216155730_create_authorization_codes_table.up.sql",
		"20260301120000_create_access_tokens_table.up.sql",
	}

	for _, file := range migrationFiles {
		migrationFile := filepath.Join(migrationsPath, file)
		migrationSQL, err := os.ReadFile(migrationFile)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file, err)
		}

		_, err = db.Exec(ctx, string(migrationSQL))
		if err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", file, err)
		}
	}

	return nil
}

func setupTest(t *testing.T) (*Queries, func()) {
	t.Helper()

	// Begin transaction
	tx, err := testDB.Begin(context.Background())
	require.NoError(t, err)

	// Create queries instance with transaction
	queries := New(tx)

	// Return cleanup function
	cleanup := func() {
		tx.Rollback(context.Background())
	}

	return queries, cleanup
}

func TestCreateUser(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("create user with all fields", func(t *testing.T) {
		firstName := "John"
		lastName := "Doe"
		provider := "google"
		providerID := "123456789"
		providerData := &models.OAuthProviderData{}
		email := "john.doe@example.com"
		locale := "en-US"
		lastLoginAt := time.Now()

		params := CreateUserParams{
			Email:         email,
			EmailVerified: true,
			FirstName:     &firstName,
			LastName:      &lastName,
			Provider:      &provider,
			ProviderID:    &providerID,
			ProviderData:  providerData,
			Locale:        locale,
			LastLoginAt:   lastLoginAt,
		}

		user, err := queries.CreateUser(ctx, params)
		require.NoError(t, err)

		assert.NotEqual(t, uuid.Nil, user.ID)
		assert.Equal(t, email, user.Email)
		assert.True(t, user.EmailVerified)
		assert.Equal(t, &firstName, user.FirstName)
		assert.Equal(t, &lastName, user.LastName)
		assert.Equal(t, &provider, user.Provider)
		assert.Equal(t, &providerID, user.ProviderID)
		assert.Equal(t, locale, user.Locale)
		assert.True(t, user.IsActive)
		assert.WithinDuration(t, lastLoginAt, user.LastLoginAt, time.Second)
		assert.NotZero(t, user.CreatedAt)
		assert.NotZero(t, user.UpdatedAt)
	})

	t.Run("create user with minimal fields", func(t *testing.T) {
		email := "jane.doe@example.com"
		locale := "en-US"
		lastLoginAt := time.Now()

		params := CreateUserParams{
			Email:         email,
			EmailVerified: false,
			FirstName:     nil,
			LastName:      nil,
			Provider:      nil,
			ProviderID:    nil,
			ProviderData:  nil,
			Locale:        locale,
			LastLoginAt:   lastLoginAt,
		}

		user, err := queries.CreateUser(ctx, params)
		require.NoError(t, err)

		assert.NotEqual(t, uuid.Nil, user.ID)
		assert.Equal(t, email, user.Email)
		assert.False(t, user.EmailVerified)
		assert.Nil(t, user.FirstName)
		assert.Nil(t, user.LastName)
		assert.Nil(t, user.Provider)
		assert.Nil(t, user.ProviderID)
		assert.Equal(t, locale, user.Locale)
		assert.True(t, user.IsActive)
	})

	t.Run("create user with duplicate email should fail", func(t *testing.T) {
		email := "duplicate@example.com"
		locale := "en-US"
		lastLoginAt := time.Now()

		params := CreateUserParams{
			Email:         email,
			EmailVerified: false,
			Locale:        locale,
			LastLoginAt:   lastLoginAt,
		}

		// Create first user
		_, err := queries.CreateUser(ctx, params)
		require.NoError(t, err)

		// Try to create duplicate
		_, err = queries.CreateUser(ctx, params)
		require.Error(t, err)
	})
}

func TestGetUserByID(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("get existing user by ID", func(t *testing.T) {
		// Create a user first
		email := "user.byid@example.com"
		params := CreateUserParams{
			Email:         email,
			EmailVerified: true,
			Locale:        "en-US",
			LastLoginAt:   time.Now(),
		}

		createdUser, err := queries.CreateUser(ctx, params)
		require.NoError(t, err)

		// Retrieve the user
		user, err := queries.GetUserByID(ctx, createdUser.ID)
		require.NoError(t, err)

		assert.Equal(t, createdUser.ID, user.ID)
		assert.Equal(t, email, user.Email)
		assert.True(t, user.EmailVerified)
	})

	t.Run("get non-existent user by ID", func(t *testing.T) {
		nonExistentID := uuid.New()

		_, err := queries.GetUserByID(ctx, nonExistentID)
		require.Error(t, err)
	})
}

func TestGetUserByEmail(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("get existing user by email", func(t *testing.T) {
		// Create a user first
		email := "user.byemail@example.com"
		firstName := "Test"
		params := CreateUserParams{
			Email:         email,
			EmailVerified: true,
			FirstName:     &firstName,
			Locale:        "en-US",
			LastLoginAt:   time.Now(),
		}

		createdUser, err := queries.CreateUser(ctx, params)
		require.NoError(t, err)

		// Retrieve the user
		user, err := queries.GetUserByEmail(ctx, email)
		require.NoError(t, err)

		assert.Equal(t, createdUser.ID, user.ID)
		assert.Equal(t, email, user.Email)
		assert.Equal(t, &firstName, user.FirstName)
	})

	t.Run("get non-existent user by email", func(t *testing.T) {
		_, err := queries.GetUserByEmail(ctx, "nonexistent@example.com")
		require.Error(t, err)
	})
}

func TestGetUserByProviderID(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("get existing user by provider ID", func(t *testing.T) {
		// Create a user first
		email := "user.byprovider@example.com"
		provider := "google"
		providerID := "google123"
		params := CreateUserParams{
			Email:         email,
			EmailVerified: true,
			Provider:      &provider,
			ProviderID:    &providerID,
			Locale:        "en-US",
			LastLoginAt:   time.Now(),
		}

		createdUser, err := queries.CreateUser(ctx, params)
		require.NoError(t, err)

		// Retrieve the user
		user, err := queries.GetUserByProviderID(ctx, GetUserByProviderIDParams{
			Provider:   &provider,
			ProviderID: &providerID,
		})
		require.NoError(t, err)

		assert.Equal(t, createdUser.ID, user.ID)
		assert.Equal(t, email, user.Email)
		assert.Equal(t, &provider, user.Provider)
		assert.Equal(t, &providerID, user.ProviderID)
	})

	t.Run("get non-existent user by provider ID", func(t *testing.T) {
		provider := "google"
		providerID := "nonexistent123"

		_, err := queries.GetUserByProviderID(ctx, GetUserByProviderIDParams{
			Provider:   &provider,
			ProviderID: &providerID,
		})
		require.Error(t, err)
	})
}

func TestUpdateUser(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("update user successfully", func(t *testing.T) {
		// Create a user first
		email := "original@example.com"
		firstName := "Original"
		params := CreateUserParams{
			Email:         email,
			EmailVerified: false,
			FirstName:     &firstName,
			Locale:        "en-US",
			LastLoginAt:   time.Now(),
		}

		createdUser, err := queries.CreateUser(ctx, params)
		require.NoError(t, err)

		// Update the user
		newEmail := "updated@example.com"
		newFirstName := "Updated"
		newLastName := "Name"
		newLocale := "fr-FR"

		updateParams := UpdateUserParams{
			ID:            createdUser.ID,
			Email:         newEmail,
			EmailVerified: true,
			FirstName:     &newFirstName,
			LastName:      &newLastName,
			Locale:        newLocale,
		}

		updatedUser, err := queries.UpdateUser(ctx, updateParams)
		require.NoError(t, err)

		assert.Equal(t, createdUser.ID, updatedUser.ID)
		assert.Equal(t, newEmail, updatedUser.Email)
		assert.True(t, updatedUser.EmailVerified)
		assert.Equal(t, &newFirstName, updatedUser.FirstName)
		assert.Equal(t, &newLastName, updatedUser.LastName)
		assert.Equal(t, newLocale, updatedUser.Locale)
	})

	t.Run("update user with nil values", func(t *testing.T) {
		// Create a user first
		email := "withnull@example.com"
		firstName := "First"
		lastName := "Last"
		params := CreateUserParams{
			Email:         email,
			EmailVerified: true,
			FirstName:     &firstName,
			LastName:      &lastName,
			Locale:        "en-US",
			LastLoginAt:   time.Now(),
		}

		createdUser, err := queries.CreateUser(ctx, params)
		require.NoError(t, err)

		// Update with nil names
		updateParams := UpdateUserParams{
			ID:            createdUser.ID,
			Email:         email,
			EmailVerified: true,
			FirstName:     nil,
			LastName:      nil,
			Locale:        "en-US",
		}

		updatedUser, err := queries.UpdateUser(ctx, updateParams)
		require.NoError(t, err)

		assert.Nil(t, updatedUser.FirstName)
		assert.Nil(t, updatedUser.LastName)
	})

	t.Run("update non-existent user", func(t *testing.T) {
		nonExistentID := uuid.New()

		updateParams := UpdateUserParams{
			ID:            nonExistentID,
			Email:         "test@example.com",
			EmailVerified: true,
			Locale:        "en-US",
		}

		_, err := queries.UpdateUser(ctx, updateParams)
		require.Error(t, err)
	})
}

func TestUpdateLastLogin(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("update last login successfully", func(t *testing.T) {
		// Create a user first
		email := "login@example.com"
		provider := "google"
		providerID := "google456"
		initialProviderData := &models.OAuthProviderData{}
		initialLoginTime := time.Now().Add(-24 * time.Hour)

		params := CreateUserParams{
			Email:         email,
			EmailVerified: true,
			Provider:      &provider,
			ProviderID:    &providerID,
			ProviderData:  initialProviderData,
			Locale:        "en-US",
			LastLoginAt:   initialLoginTime,
		}

		createdUser, err := queries.CreateUser(ctx, params)
		require.NoError(t, err)

		// Update last login
		newProviderData := &models.OAuthProviderData{}
		newLoginTime := time.Now()

		updateParams := UpdateLastLoginParams{
			ID:           createdUser.ID,
			ProviderData: newProviderData,
			LastLoginAt:  newLoginTime,
		}

		updatedUser, err := queries.UpdateLastLogin(ctx, updateParams)
		require.NoError(t, err)

		assert.Equal(t, createdUser.ID, updatedUser.ID)
		assert.WithinDuration(t, newLoginTime, updatedUser.LastLoginAt, time.Second)
		assert.NotNil(t, updatedUser.ProviderData)
	})

	t.Run("update last login with nil provider data", func(t *testing.T) {
		// Create a user first
		email := "login2@example.com"
		params := CreateUserParams{
			Email:         email,
			EmailVerified: true,
			Locale:        "en-US",
			LastLoginAt:   time.Now(),
		}

		createdUser, err := queries.CreateUser(ctx, params)
		require.NoError(t, err)

		// Update with nil provider data
		newLoginTime := time.Now()

		updateParams := UpdateLastLoginParams{
			ID:           createdUser.ID,
			ProviderData: nil,
			LastLoginAt:  newLoginTime,
		}

		updatedUser, err := queries.UpdateLastLogin(ctx, updateParams)
		require.NoError(t, err)

		assert.Equal(t, createdUser.ID, updatedUser.ID)
		assert.WithinDuration(t, newLoginTime, updatedUser.LastLoginAt, time.Second)
	})

	t.Run("update last login for non-existent user", func(t *testing.T) {
		nonExistentID := uuid.New()

		updateParams := UpdateLastLoginParams{
			ID:          nonExistentID,
			LastLoginAt: time.Now(),
		}

		_, err := queries.UpdateLastLogin(ctx, updateParams)
		require.Error(t, err)
	})
}

func TestListUsers(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Create test users
	isAdminTrue := true
	activeUsers := []CreateUserParams{
		{Email: "active1@example.com", EmailVerified: true, Locale: "en-US", LastLoginAt: time.Now()},
		{Email: "active2@example.com", EmailVerified: true, Locale: "en-US", LastLoginAt: time.Now()},
	}
	var createdUserIDs []uuid.UUID
	for _, p := range activeUsers {
		u, err := queries.CreateUser(ctx, p)
		require.NoError(t, err)
		createdUserIDs = append(createdUserIDs, u.ID)
	}
	// Make one user admin via transaction-scoped exec
	_, err := queries.db.Exec(ctx, "UPDATE users SET is_admin = true WHERE id = $1", createdUserIDs[0])
	require.NoError(t, err)
	_ = isAdminTrue

	t.Run("list active non-admin users with pagination", func(t *testing.T) {
		// Column1=true filters is_active=true; Column2=false filters is_admin=false
		users, err := queries.ListUsers(ctx, ListUsersParams{
			Column1: true,
			Column2: false,
			Limit:   100,
			Offset:  0,
		})
		require.NoError(t, err)
		// The 2 active non-admin users we created should be in the result
		assert.GreaterOrEqual(t, len(users), 1)
	})

	t.Run("list users with limit", func(t *testing.T) {
		users, err := queries.ListUsers(ctx, ListUsersParams{
			Column1: true,
			Column2: false,
			Limit:   1,
			Offset:  0,
		})
		require.NoError(t, err)
		assert.Len(t, users, 1)
	})

	t.Run("list users with offset", func(t *testing.T) {
		allUsers, err := queries.ListUsers(ctx, ListUsersParams{Column1: true, Column2: false, Limit: 100, Offset: 0})
		require.NoError(t, err)
		if len(allUsers) > 0 {
			offsetUsers, err := queries.ListUsers(ctx, ListUsersParams{Column1: true, Column2: false, Limit: 100, Offset: 1})
			require.NoError(t, err)
			assert.Equal(t, len(allUsers)-1, len(offsetUsers))
		}
	})
}

func TestCountUsers(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Create some users
	for i := 0; i < 3; i++ {
		_, err := queries.CreateUser(ctx, CreateUserParams{
			Email:         fmt.Sprintf("countuser%d@example.com", i),
			EmailVerified: true,
			Locale:        "en-US",
			LastLoginAt:   time.Now(),
		})
		require.NoError(t, err)
	}

	t.Run("count all active non-admin users", func(t *testing.T) {
		// Column1=true: is_active=true, Column2=false: is_admin=false
		count, err := queries.CountUsers(ctx, CountUsersParams{Column1: true, Column2: false})
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, int64(3))
	})
}

func TestGetUsersByAdmin(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	// Create a regular user and an admin user
	_, err := queries.CreateUser(ctx, CreateUserParams{
		Email: "regular_getbyadmin@example.com", EmailVerified: true, Locale: "en-US", LastLoginAt: time.Now(),
	})
	require.NoError(t, err)

	adminUser, err := queries.CreateUser(ctx, CreateUserParams{
		Email: "admin_getbyadmin@example.com", EmailVerified: true, Locale: "en-US", LastLoginAt: time.Now(),
	})
	require.NoError(t, err)
	// Use transaction-scoped exec so the user created within the transaction is visible
	_, err = queries.db.Exec(ctx, "UPDATE users SET is_admin = true WHERE id = $1", adminUser.ID)
	require.NoError(t, err)

	t.Run("get admin users", func(t *testing.T) {
		isAdmin := true
		admins, err := queries.GetUsersByAdmin(ctx, &isAdmin)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(admins), 1)
		for _, u := range admins {
			assert.NotNil(t, u.IsAdmin)
			assert.True(t, *u.IsAdmin)
		}
	})

	t.Run("get non-admin users", func(t *testing.T) {
		isAdmin := false
		nonAdmins, err := queries.GetUsersByAdmin(ctx, &isAdmin)
		require.NoError(t, err)
		for _, u := range nonAdmins {
			if u.IsAdmin != nil {
				assert.False(t, *u.IsAdmin)
			}
		}
	})
}

func TestUpdateUserActiveStatus(t *testing.T) {
	queries, cleanup := setupTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("deactivate user", func(t *testing.T) {
		user, err := queries.CreateUser(ctx, CreateUserParams{
			Email: "deactivate@example.com", EmailVerified: true, Locale: "en-US", LastLoginAt: time.Now(),
		})
		require.NoError(t, err)
		assert.True(t, user.IsActive)

		updated, err := queries.UpdateUserActiveStatus(ctx, UpdateUserActiveStatusParams{
			ID:       user.ID,
			IsActive: false,
		})
		require.NoError(t, err)
		assert.False(t, updated.IsActive)
	})

	t.Run("reactivate user", func(t *testing.T) {
		user, err := queries.CreateUser(ctx, CreateUserParams{
			Email: "reactivate@example.com", EmailVerified: true, Locale: "en-US", LastLoginAt: time.Now(),
		})
		require.NoError(t, err)

		// Deactivate first
		_, err = queries.UpdateUserActiveStatus(ctx, UpdateUserActiveStatusParams{ID: user.ID, IsActive: false})
		require.NoError(t, err)

		// Reactivate
		updated, err := queries.UpdateUserActiveStatus(ctx, UpdateUserActiveStatusParams{ID: user.ID, IsActive: true})
		require.NoError(t, err)
		assert.True(t, updated.IsActive)
	})

	t.Run("update non-existent user returns no error but zero rows", func(t *testing.T) {
		nonExistentID := uuid.New()
		_, err := queries.UpdateUserActiveStatus(ctx, UpdateUserActiveStatusParams{
			ID:       nonExistentID,
			IsActive: false,
		})
		// pgx returns no rows error
		require.Error(t, err)
	})
}
