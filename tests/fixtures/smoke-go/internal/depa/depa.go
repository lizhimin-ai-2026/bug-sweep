package depa

import (
	"strings"

	"example.com/smoke/internal/depb"
)

// Normalize trims and canonicalizes a region label.
func Normalize(region string) string {
	return depb.Canonical(strings.TrimSpace(region))
}
