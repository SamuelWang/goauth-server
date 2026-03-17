package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStrPtr_NonEmpty(t *testing.T) {
	result := StrPtr("hello")
	require.NotNil(t, result)
	assert.Equal(t, "hello", *result)
}

func TestStrPtr_Empty(t *testing.T) {
	result := StrPtr("")
	assert.Nil(t, result)
}

func TestStrPtr_Whitespace(t *testing.T) {
	result := StrPtr("   ")
	require.NotNil(t, result)
	assert.Equal(t, "   ", *result)
}
