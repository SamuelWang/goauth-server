// Package password provides password policy validation for user-supplied passwords.
package password

import (
	_ "embed"
	"errors"
	"strings"
	"unicode"
)

//go:embed denylist.txt
var denylistRaw string

// denySet is built once at package initialisation from the embedded denylist.
var denySet map[string]struct{}

func init() {
	denySet = make(map[string]struct{})
	for _, line := range strings.Split(denylistRaw, "\n") {
		entry := strings.TrimSpace(line)
		if entry != "" {
			denySet[strings.ToLower(entry)] = struct{}{}
		}
	}
}

// specialChars is the set of permitted special characters for the complexity rule.
const specialChars = `!@#$%^&*()-_=+[]{}|;:'",.<>?/~` + "`"

// Validate checks that password satisfies the full password policy:
//
//  1. At least 12 characters (Unicode code points).
//  2. At least one ASCII uppercase letter (A-Z).
//  3. At least one ASCII lowercase letter (a-z).
//  4. At least one ASCII digit (0-9).
//  5. At least one character from the allowed special-character set.
//  6. Not present in the embedded common-password denylist (case-insensitive).
//  7. Does not contain the local-part of userEmail (case-insensitive).
//
// userEmail may be empty; when empty, rule 7 is skipped.
// Returns a descriptive error naming the first failed rule, or nil on success.
func Validate(password, userEmail string) error {
	if len([]rune(password)) < 12 {
		return errors.New("password must be at least 12 characters long")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r) && r <= 'Z':
			hasUpper = true
		case unicode.IsLower(r) && r >= 'a':
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case strings.ContainsRune(specialChars, r):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter (A-Z)")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter (a-z)")
	}
	if !hasDigit {
		return errors.New("password must contain at least one digit (0-9)")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	if _, found := denySet[strings.ToLower(password)]; found {
		return errors.New("password is too common; please choose a more unique password")
	}

	if userEmail != "" {
		localPart := userEmail
		if idx := strings.Index(userEmail, "@"); idx != -1 {
			localPart = userEmail[:idx]
		}
		if localPart != "" && strings.Contains(strings.ToLower(password), strings.ToLower(localPart)) {
			return errors.New("password must not contain your email address")
		}
	}

	return nil
}
