package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SamuelWang/goauth-server/internal/repository"
	"github.com/SamuelWang/goauth-server/internal/testutil/mocks"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// testEncryptionKey is a 32-byte key for AES-256-GCM used in tests.
var testEncryptionKey = []byte("01234567890123456789012345678901")

func newTestService(t *testing.T, q *mocks.MockQuerier) *Service {
	t.Helper()
	svc, err := New(q, testEncryptionKey, "development")
	require.NoError(t, err)
	return svc
}

func sampleProvider(clientID uuid.UUID) repository.OauthProvider {
	isEnabled := true
	return repository.OauthProvider{
		ID:                   uuid.New(),
		ClientID:             clientID,
		Name:                 "google",
		DisplayName:          "Google",
		ProviderClientID:     "goog-client-id",
		ProviderClientSecret: "encrypted-secret", // raw value; tests using decrypt path override this
		AuthUrl:              "https://accounts.google.com/o/oauth2/auth",
		TokenUrl:             "https://oauth2.googleapis.com/token",
		UserInfoUrl:          "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:               []string{"openid", "email", "profile"},
		IsEnabled:            &isEnabled,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
}

func TestNew_InvalidKeyLength(t *testing.T) {
	_, err := New(&mocks.MockQuerier{}, []byte("tooshort"), "development")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestListProvidersByClient(t *testing.T) {
	clientID := uuid.New()
	row := sampleProvider(clientID)

	t.Run("returns providers for client", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("ListOAuthProvidersByClient", mock.Anything, clientID).Return([]repository.OauthProvider{row}, nil)

		svc := newTestService(t, q)
		providers, err := svc.ListProvidersByClient(context.Background(), clientID)
		require.NoError(t, err)
		require.Len(t, providers, 1)
		assert.Equal(t, row.ID, providers[0].ID)
		assert.Equal(t, row.Name, providers[0].Name)
		q.AssertExpectations(t)
	})

	t.Run("propagates repo error", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("ListOAuthProvidersByClient", mock.Anything, clientID).Return(nil, errors.New("db error"))

		svc := newTestService(t, q)
		_, err := svc.ListProvidersByClient(context.Background(), clientID)
		require.Error(t, err)
		q.AssertExpectations(t)
	})
}

func TestListEnabledProvidersByClient(t *testing.T) {
	clientID := uuid.New()
	row := sampleProvider(clientID)

	q := &mocks.MockQuerier{}
	q.On("ListEnabledOAuthProvidersByClient", mock.Anything, clientID).Return([]repository.OauthProvider{row}, nil)

	svc := newTestService(t, q)
	providers, err := svc.ListEnabledProvidersByClient(context.Background(), clientID)
	require.NoError(t, err)
	require.Len(t, providers, 1)
	assert.True(t, providers[0].IsEnabled)
	q.AssertExpectations(t)
}

func TestGetProvider(t *testing.T) {
	clientID := uuid.New()
	row := sampleProvider(clientID)

	t.Run("found", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)

		svc := newTestService(t, q)
		p, err := svc.GetProvider(context.Background(), row.ID)
		require.NoError(t, err)
		assert.Equal(t, row.ID, p.ID)
		q.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(repository.OauthProvider{}, pgx.ErrNoRows)

		svc := newTestService(t, q)
		_, err := svc.GetProvider(context.Background(), row.ID)
		assert.ErrorIs(t, err, ErrProviderNotFound)
		q.AssertExpectations(t)
	})
}

func TestGetProviderByClientAndName(t *testing.T) {
	clientID := uuid.New()
	row := sampleProvider(clientID)
	params := repository.GetOAuthProviderByClientAndNameParams{ClientID: clientID, Name: "google"}

	t.Run("found", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProviderByClientAndName", mock.Anything, params).Return(row, nil)

		svc := newTestService(t, q)
		p, err := svc.GetProviderByClientAndName(context.Background(), clientID, "google")
		require.NoError(t, err)
		assert.Equal(t, row.ID, p.ID)
		q.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProviderByClientAndName", mock.Anything, params).Return(repository.OauthProvider{}, pgx.ErrNoRows)

		svc := newTestService(t, q)
		_, err := svc.GetProviderByClientAndName(context.Background(), clientID, "google")
		assert.ErrorIs(t, err, ErrProviderNotFound)
		q.AssertExpectations(t)
	})
}

func TestGetProviderWithSecret(t *testing.T) {
	clientID := uuid.New()
	plainSecret := "my-secret-value"

	// Encrypt the secret as the service would store it.
	encryptedSecret, err := encrypt(testEncryptionKey, plainSecret)
	require.NoError(t, err)

	row := sampleProvider(clientID)
	row.ProviderClientSecret = encryptedSecret

	t.Run("returns decrypted secret", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)

		svc := newTestService(t, q)
		p, err := svc.GetProviderWithSecret(context.Background(), row.ID)
		require.NoError(t, err)
		assert.Equal(t, plainSecret, p.ProviderClientSecret)
		assert.Equal(t, row.ProviderClientID, p.ProviderClientID)
		q.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(repository.OauthProvider{}, pgx.ErrNoRows)

		svc := newTestService(t, q)
		_, err := svc.GetProviderWithSecret(context.Background(), row.ID)
		assert.ErrorIs(t, err, ErrProviderNotFound)
		q.AssertExpectations(t)
	})
}

func TestGetProviderWithSecretByClientAndName(t *testing.T) {
	clientID := uuid.New()
	plainSecret := "provider-secret"
	encryptedSecret, err := encrypt(testEncryptionKey, plainSecret)
	require.NoError(t, err)

	row := sampleProvider(clientID)
	row.ProviderClientSecret = encryptedSecret
	params := repository.GetOAuthProviderByClientAndNameParams{ClientID: clientID, Name: "google"}

	t.Run("found with decrypted secret", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProviderByClientAndName", mock.Anything, params).Return(row, nil)

		svc := newTestService(t, q)
		p, err := svc.GetProviderWithSecretByClientAndName(context.Background(), clientID, "google")
		require.NoError(t, err)
		assert.Equal(t, plainSecret, p.ProviderClientSecret)
		q.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProviderByClientAndName", mock.Anything, params).Return(repository.OauthProvider{}, pgx.ErrNoRows)

		svc := newTestService(t, q)
		_, err := svc.GetProviderWithSecretByClientAndName(context.Background(), clientID, "google")
		assert.ErrorIs(t, err, ErrProviderNotFound)
		q.AssertExpectations(t)
	})
}

func TestCreateProvider(t *testing.T) {
	clientID := uuid.New()
	dto := CreateProviderDTO{
		Name:                 "google",
		DisplayName:          "Google",
		ProviderClientID:     "goog-client-id",
		ProviderClientSecret: "secret",
		AuthURL:              "https://accounts.google.com/o/oauth2/auth",
		TokenURL:             "https://oauth2.googleapis.com/token",
		UserInfoURL:          "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:               []string{"openid", "email"},
		IsEnabled:            true,
	}

	t.Run("success", func(t *testing.T) {
		created := sampleProvider(clientID)
		q := &mocks.MockQuerier{}
		q.On("CreateOAuthProvider", mock.Anything, mock.MatchedBy(func(p repository.CreateOAuthProviderParams) bool {
			return p.ClientID == clientID && p.Name == dto.Name
		})).Return(created, nil)

		svc := newTestService(t, q)
		p, err := svc.CreateProvider(context.Background(), clientID, dto)
		require.NoError(t, err)
		assert.Equal(t, created.ID, p.ID)
		q.AssertExpectations(t)
	})

	t.Run("duplicate name returns ErrDuplicateProviderName", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		pgErr := &pgconn.PgError{Code: "23505"}
		q.On("CreateOAuthProvider", mock.Anything, mock.Anything).Return(repository.OauthProvider{}, pgErr)

		svc := newTestService(t, q)
		_, err := svc.CreateProvider(context.Background(), clientID, dto)
		assert.ErrorIs(t, err, ErrDuplicateProviderName)
		q.AssertExpectations(t)
	})

	t.Run("validation error: missing name", func(t *testing.T) {
		invalidDTO := dto
		invalidDTO.Name = ""
		svc := newTestService(t, &mocks.MockQuerier{})
		_, err := svc.CreateProvider(context.Background(), clientID, invalidDTO)
		require.Error(t, err)
		var ve *ValidationError
		assert.True(t, errors.As(err, &ve))
		assert.Equal(t, "name", ve.Field)
	})

	t.Run("validation error: missing scopes", func(t *testing.T) {
		invalidDTO := dto
		invalidDTO.Scopes = nil
		svc := newTestService(t, &mocks.MockQuerier{})
		_, err := svc.CreateProvider(context.Background(), clientID, invalidDTO)
		require.Error(t, err)
		var ve *ValidationError
		assert.True(t, errors.As(err, &ve))
		assert.Equal(t, "scopes", ve.Field)
	})
}

func TestUpdateProvider(t *testing.T) {
	clientID := uuid.New()
	row := sampleProvider(clientID)
	dto := UpdateProviderDTO{
		DisplayName:      "Google Updated",
		ProviderClientID: "new-client-id",
		AuthURL:          "https://accounts.google.com/o/oauth2/auth",
		TokenURL:         "https://oauth2.googleapis.com/token",
		UserInfoURL:      "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:           []string{"openid"},
		IsEnabled:        true,
	}

	t.Run("success without secret change", func(t *testing.T) {
		updated := row
		updated.DisplayName = dto.DisplayName
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)
		q.On("UpdateOAuthProvider", mock.Anything, mock.Anything).Return(updated, nil)

		svc := newTestService(t, q)
		p, err := svc.UpdateProvider(context.Background(), row.ID, clientID, dto)
		require.NoError(t, err)
		assert.Equal(t, "Google Updated", p.DisplayName)
		q.AssertExpectations(t)
	})

	t.Run("success with new secret", func(t *testing.T) {
		dtoWithSecret := dto
		dtoWithSecret.ProviderClientSecret = "new-secret"
		updated := row
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)
		q.On("UpdateOAuthProvider", mock.Anything, mock.Anything).Return(updated, nil)

		svc := newTestService(t, q)
		_, err := svc.UpdateProvider(context.Background(), row.ID, clientID, dtoWithSecret)
		require.NoError(t, err)
		q.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(repository.OauthProvider{}, pgx.ErrNoRows)

		svc := newTestService(t, q)
		_, err := svc.UpdateProvider(context.Background(), row.ID, clientID, dto)
		assert.ErrorIs(t, err, ErrProviderNotFound)
		q.AssertExpectations(t)
	})

	t.Run("client mismatch", func(t *testing.T) {
		wrongClientID := uuid.New()
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil) // row has clientID

		svc := newTestService(t, q)
		_, err := svc.UpdateProvider(context.Background(), row.ID, wrongClientID, dto)
		assert.ErrorIs(t, err, ErrProviderClientMismatch)
		q.AssertExpectations(t)
	})
}

func TestEnableProvider(t *testing.T) {
	clientID := uuid.New()
	row := sampleProvider(clientID)

	t.Run("success", func(t *testing.T) {
		updated := row
		isEnabled := true
		updated.IsEnabled = &isEnabled
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)
		q.On("UpdateOAuthProvider", mock.Anything, mock.Anything).Return(updated, nil)

		svc := newTestService(t, q)
		err := svc.EnableProvider(context.Background(), row.ID, clientID)
		require.NoError(t, err)
		q.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(repository.OauthProvider{}, pgx.ErrNoRows)

		svc := newTestService(t, q)
		err := svc.EnableProvider(context.Background(), row.ID, clientID)
		assert.ErrorIs(t, err, ErrProviderNotFound)
		q.AssertExpectations(t)
	})

	t.Run("client mismatch", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)

		svc := newTestService(t, q)
		err := svc.EnableProvider(context.Background(), row.ID, uuid.New())
		assert.ErrorIs(t, err, ErrProviderClientMismatch)
		q.AssertExpectations(t)
	})
}

func TestDisableProvider(t *testing.T) {
	clientID := uuid.New()
	row := sampleProvider(clientID)

	t.Run("success", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)
		q.On("DisableOAuthProvider", mock.Anything, row.ID).Return(nil)

		svc := newTestService(t, q)
		err := svc.DisableProvider(context.Background(), row.ID, clientID)
		require.NoError(t, err)
		q.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(repository.OauthProvider{}, pgx.ErrNoRows)

		svc := newTestService(t, q)
		err := svc.DisableProvider(context.Background(), row.ID, clientID)
		assert.ErrorIs(t, err, ErrProviderNotFound)
		q.AssertExpectations(t)
	})

	t.Run("client mismatch", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)

		svc := newTestService(t, q)
		err := svc.DisableProvider(context.Background(), row.ID, uuid.New())
		assert.ErrorIs(t, err, ErrProviderClientMismatch)
		q.AssertExpectations(t)
	})
}

func TestDeleteProvider(t *testing.T) {
	clientID := uuid.New()
	row := sampleProvider(clientID)

	t.Run("success", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)
		q.On("DeleteOAuthProvider", mock.Anything, row.ID).Return(nil)

		svc := newTestService(t, q)
		err := svc.DeleteProvider(context.Background(), row.ID, clientID)
		require.NoError(t, err)
		q.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(repository.OauthProvider{}, pgx.ErrNoRows)

		svc := newTestService(t, q)
		err := svc.DeleteProvider(context.Background(), row.ID, clientID)
		assert.ErrorIs(t, err, ErrProviderNotFound)
		q.AssertExpectations(t)
	})

	t.Run("client mismatch", func(t *testing.T) {
		q := &mocks.MockQuerier{}
		q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)

		svc := newTestService(t, q)
		err := svc.DeleteProvider(context.Background(), row.ID, uuid.New())
		assert.ErrorIs(t, err, ErrProviderClientMismatch)
		q.AssertExpectations(t)
	})
}

// --- Validation edge cases ---

func TestValidationError_ErrorString(t *testing.T) {
	ve := &ValidationError{Field: "name", Message: "required"}
	assert.Equal(t, "name: required", ve.Error())
}

func TestCreateProvider_ValidationErrors(t *testing.T) {
	clientID := uuid.New()
	base := CreateProviderDTO{
		Name:                 "google",
		DisplayName:          "Google",
		ProviderClientID:     "cid",
		ProviderClientSecret: "secret",
		AuthURL:              "https://auth.example.com",
		TokenURL:             "https://token.example.com",
		UserInfoURL:          "https://userinfo.example.com",
		Scopes:               []string{"openid"},
	}

	cases := []struct {
		name  string
		patch func(*CreateProviderDTO)
		field string
	}{
		{"missing display_name", func(d *CreateProviderDTO) { d.DisplayName = "" }, "display_name"},
		{"missing provider_client_id", func(d *CreateProviderDTO) { d.ProviderClientID = "" }, "provider_client_id"},
		{"missing provider_client_secret", func(d *CreateProviderDTO) { d.ProviderClientSecret = "" }, "provider_client_secret"},
		{"invalid auth_url", func(d *CreateProviderDTO) { d.AuthURL = "not-a-url" }, "auth_url"},
		{"invalid token_url", func(d *CreateProviderDTO) { d.TokenURL = "ftp://bad" }, "token_url"},
		{"empty user_info_url", func(d *CreateProviderDTO) { d.UserInfoURL = "" }, "user_info_url"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dto := base
			tc.patch(&dto)
			svc := newTestService(t, &mocks.MockQuerier{})
			_, err := svc.CreateProvider(context.Background(), clientID, dto)
			require.Error(t, err)
			var ve *ValidationError
			require.True(t, errors.As(err, &ve))
			assert.Equal(t, tc.field, ve.Field)
		})
	}
}

func TestUpdateProvider_ValidationErrors(t *testing.T) {
	clientID := uuid.New()
	row := sampleProvider(clientID)
	base := UpdateProviderDTO{
		DisplayName:      "Google",
		ProviderClientID: "cid",
		AuthURL:          "https://auth.example.com",
		TokenURL:         "https://token.example.com",
		UserInfoURL:      "https://userinfo.example.com",
		Scopes:           []string{"openid"},
	}

	cases := []struct {
		name  string
		patch func(*UpdateProviderDTO)
		field string
	}{
		{"missing display_name", func(d *UpdateProviderDTO) { d.DisplayName = "" }, "display_name"},
		{"missing provider_client_id", func(d *UpdateProviderDTO) { d.ProviderClientID = "" }, "provider_client_id"},
		{"invalid auth_url", func(d *UpdateProviderDTO) { d.AuthURL = "" }, "auth_url"},
		{"invalid token_url", func(d *UpdateProviderDTO) { d.TokenURL = "not-a-url" }, "token_url"},
		{"invalid user_info_url scheme", func(d *UpdateProviderDTO) { d.UserInfoURL = "ftp://example.com" }, "user_info_url"},
		{"empty scopes", func(d *UpdateProviderDTO) { d.Scopes = nil }, "scopes"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dto := base
			tc.patch(&dto)
			q := &mocks.MockQuerier{}
			q.On("GetOAuthProvider", mock.Anything, row.ID).Return(row, nil)
			svc := newTestService(t, q)
			_, err := svc.UpdateProvider(context.Background(), row.ID, clientID, dto)
			require.Error(t, err)
			var ve *ValidationError
			require.True(t, errors.As(err, &ve))
			assert.Equal(t, tc.field, ve.Field)
		})
	}
}
