package depb

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"example.com/smoke/internal/service"
)

// ModuleTag identifies the producing module in report output.
func ModuleTag() string {
	return service.ModuleName + "/depb"
}

// Canonical lower-cases and trims a region label.
func Canonical(region string) string {
	return strings.ToLower(strings.TrimSpace(region))
}

// Slugify converts a region label into a URL-safe slug.
func Slugify(region string) string {
	slug := Canonical(region)
	slug = strings.ReplaceAll(slug, " ", "-")
	slug = strings.ReplaceAll(slug, "/", "-")
	return slug
}

// ShortHash returns a stable 16-character digest of the given text.
func ShortHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])[:16]
}
