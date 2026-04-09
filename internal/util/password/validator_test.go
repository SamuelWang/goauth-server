package password_test

import (
	"testing"

	"github.com/SamuelWang/goauth-server/internal/util/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate_TooShort(t *testing.T) {
	err := password.Validate("Sh0rt!Xx", "user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "12 characters")
}

func TestValidate_MissingUppercase(t *testing.T) {
	err := password.Validate("nouppercase1!", "user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uppercase")
}

func TestValidate_MissingLowercase(t *testing.T) {
	err := password.Validate("NOLOWERCASE1!", "user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lowercase")
}

func TestValidate_MissingDigit(t *testing.T) {
	err := password.Validate("NoDigitsHere cd /home/samuelwang/projects/goauth-server && cat internal/util/password/validator_test.go", "user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "digit")
}

func TestValidate_MissingSpecialChar(t *testing.T) {
	err := password.Validate("NoSpecialChar1A", "user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "special character")
}

func TestValidate_DenyList(t *testing.T) {
	// "P@ssword1234" lowercases to "p@ssword1234" which is in the embedded denylist.
	// It satisfies all structural rules (12 chars, upper, lower, digit, special),
	// so the deny-list check is the only thing that blocks it.
	err := password.Validate("P@ssword1234", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "common")
}

func TestValidate_ContainsEmailLocalPart(t *testing.T) {
	err := password.Validate("JohnDoeIs@1secure", "johndoe@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email")
}

func TestValidate_Valid(t *testing.T) {
	err := password.Validate("Tr0ub4dor&3XYZ2!", "user@example.com")
	require.NoError(t, err)
}

// TestValidate_EmptyEmail verifies that rule 7 is skipped when email is empty.
func TestValidate_EmptyEmail(t *testing.T) {
	err := password.Validate("Tr0ub4dor&3XYZ2!", "")
	require.NoError(t, err)
}
