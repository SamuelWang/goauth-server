package util

// StrPtr returns a pointer to s, or nil when s is empty.
func StrPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
