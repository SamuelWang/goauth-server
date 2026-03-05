package provider

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

func validateCreateDTO(dto CreateProviderDTO) error {
	if strings.TrimSpace(dto.Name) == "" {
		return &ValidationError{Field: "name", Message: "required"}
	}
	if strings.TrimSpace(dto.DisplayName) == "" {
		return &ValidationError{Field: "display_name", Message: "required"}
	}
	if strings.TrimSpace(dto.ProviderClientID) == "" {
		return &ValidationError{Field: "provider_client_id", Message: "required"}
	}
	if strings.TrimSpace(dto.ProviderClientSecret) == "" {
		return &ValidationError{Field: "provider_client_secret", Message: "required"}
	}
	if err := validateURL("auth_url", dto.AuthURL); err != nil {
		return err
	}
	if err := validateURL("token_url", dto.TokenURL); err != nil {
		return err
	}
	if err := validateURL("user_info_url", dto.UserInfoURL); err != nil {
		return err
	}
	if len(dto.Scopes) == 0 {
		return &ValidationError{Field: "scopes", Message: "at least one scope is required"}
	}
	return nil
}

func validateUpdateDTO(dto UpdateProviderDTO) error {
	if strings.TrimSpace(dto.DisplayName) == "" {
		return &ValidationError{Field: "display_name", Message: "required"}
	}
	if strings.TrimSpace(dto.ProviderClientID) == "" {
		return &ValidationError{Field: "provider_client_id", Message: "required"}
	}
	// ProviderClientSecret is optional on update: empty means retain the existing secret.
	if err := validateURL("auth_url", dto.AuthURL); err != nil {
		return err
	}
	if err := validateURL("token_url", dto.TokenURL); err != nil {
		return err
	}
	if err := validateURL("user_info_url", dto.UserInfoURL); err != nil {
		return err
	}
	if len(dto.Scopes) == 0 {
		return &ValidationError{Field: "scopes", Message: "at least one scope is required"}
	}
	return nil
}

// validateURL checks that rawURL is a well-formed http or https URL.
func validateURL(field, rawURL string) error {
	if strings.TrimSpace(rawURL) == "" {
		return &ValidationError{Field: field, Message: "required"}
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Host == "" {
		return &ValidationError{Field: field, Message: "must be a valid URL"}
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return &ValidationError{Field: field, Message: "must use http or https scheme"}
	}
	return nil
}
