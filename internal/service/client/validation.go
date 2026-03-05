package client

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidationError represents an input validation failure for a specific field.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// allowedGrantTypes is the set of currently supported OAuth 2.0 grant types.
var allowedGrantTypes = map[string]struct{}{
	"authorization_code": {},
	"refresh_token":      {},
}

func validateCreateDTO(dto CreateClientDTO, env string) error {
	if strings.TrimSpace(dto.Name) == "" {
		return &ValidationError{Field: "name", Message: "required"}
	}
	if len(dto.RedirectURIs) == 0 {
		return &ValidationError{Field: "redirect_uris", Message: "at least one redirect URI is required"}
	}
	for _, uri := range dto.RedirectURIs {
		if err := validateRedirectURI("redirect_uris", uri, env); err != nil {
			return err
		}
	}
	if len(dto.GrantTypes) == 0 {
		return &ValidationError{Field: "grant_types", Message: "at least one grant type is required"}
	}
	for _, gt := range dto.GrantTypes {
		if _, ok := allowedGrantTypes[gt]; !ok {
			return &ValidationError{Field: "grant_types", Message: fmt.Sprintf("unsupported grant type: %q", gt)}
		}
	}
	return nil
}

func validateUpdateDTO(dto UpdateClientDTO, env string) error {
	if strings.TrimSpace(dto.Name) == "" {
		return &ValidationError{Field: "name", Message: "required"}
	}
	if len(dto.RedirectURIs) == 0 {
		return &ValidationError{Field: "redirect_uris", Message: "at least one redirect URI is required"}
	}
	for _, uri := range dto.RedirectURIs {
		if err := validateRedirectURI("redirect_uris", uri, env); err != nil {
			return err
		}
	}
	if len(dto.GrantTypes) == 0 {
		return &ValidationError{Field: "grant_types", Message: "at least one grant type is required"}
	}
	for _, gt := range dto.GrantTypes {
		if _, ok := allowedGrantTypes[gt]; !ok {
			return &ValidationError{Field: "grant_types", Message: fmt.Sprintf("unsupported grant type: %q", gt)}
		}
	}
	return nil
}

// validateRedirectURI checks that the URI is a valid URL.
// In production, HTTPS is required unless the host is a loopback address.
func validateRedirectURI(field, rawURI, env string) error {
	if strings.TrimSpace(rawURI) == "" {
		return &ValidationError{Field: field, Message: "redirect URI must not be empty"}
	}
	parsed, err := url.ParseRequestURI(rawURI)
	if err != nil || parsed.Host == "" {
		return &ValidationError{Field: field, Message: fmt.Sprintf("invalid redirect URI: %q", rawURI)}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return &ValidationError{Field: field, Message: fmt.Sprintf("redirect URI must use http or https scheme: %q", rawURI)}
	}
	// In production, require HTTPS unless the host is a loopback address.
	if env == "production" && parsed.Scheme == "http" {
		host := parsed.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return &ValidationError{Field: field, Message: fmt.Sprintf("redirect URI must use HTTPS in production: %q", rawURI)}
		}
	}
	return nil
}
