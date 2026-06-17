// Package web exposes the embedded static assets (CSS/JS/images) so the binary
// runs standalone from any directory (§17). Static lives at web/static and is
// embedded here because //go:embed cannot reach across package directories.
package web

import "embed"

//go:embed static
var staticFS embed.FS

// Static is the embedded web/static filesystem (css/, js/, img/).
var Static = staticFS
