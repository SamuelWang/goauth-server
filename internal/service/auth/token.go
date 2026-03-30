package auth

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const challengeTokenType = "password_change"
const challengeTokenExpiry = 15 * time.Minute

// challengeClaims are the JWT claims for a force-password-change challenge token.
type challengeClaims struct {
	TokenType string `json:"typ"`
	jwt.RegisteredClaims
}

// GenerateChallengeToken creates a short-lived HS256 JWT that gates the
// POST /auth/change-password endpoint. The token type claim is set to
// "password_change" so that ValidateAccessToken cannot accept it.
func (s *Service) GenerateChallengeToken(userID uuid.UUID) (string, error) {
	signingKey, err := hex.DecodeString(s.cfg.Security.SessionSigningKey)
	if err != nil {
		return "", fmt.Errorf("decode session signing key: %w", err)
	}
	now := time.Now().UTC()
	claims := challengeClaims{
		TokenType: challengeTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(challengeTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.cfg.App.Name,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(signingKey)
}

// ValidateChallengeToken parses and validates a challenge token, returning the
// user ID embedded in the subject claim. It rejects tokens that are expired,
// have an invalid signature, or carry a type claim other than "password_change".
func (s *Service) ValidateChallengeToken(tokenStr string) (uuid.UUID, error) {
	signingKey, err := hex.DecodeString(s.cfg.Security.SessionSigningKey)
	if err != nil {
		return uuid.Nil, fmt.Errorf("decode session signing key: %w", err)
	}

	token, err := jwt.ParseWithClaims(tokenStr, &challengeClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return signingKey, nil
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid challenge token: %w", err)
	}

	claims, ok := token.Claims.(*challengeClaims)
	if !ok || !token.Valid {
		return uuid.Nil, errors.New("invalid challenge token claims")
	}
	if claims.TokenType != challengeTokenType {
		return uuid.Nil, errors.New("challenge token has wrong type")
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("challenge token subject is not a valid UUID: %w", err)
	}
	return userID, nil
}

// Expiry returns the configured token lifetime duration.
func (s *Service) Expiry() time.Duration {
	return time.Duration(s.cfg.AccessToken.Expiry) * time.Minute
}

func (s *Service) GenerateAccessToken(userID, email string) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.Expiry())),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.cfg.App.Name,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(s.privateKey)
}

func (s *Service) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

func parsePrivateKey(privateKeyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format as fallback
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = parsedKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an ECDSA private key")
		}
	}

	return key, nil
}

func parsePublicKey(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return key, nil
}
