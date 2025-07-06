package shared

import "regexp"

var (
	// Full “semver” (x.y.z, optional -prerelease and +build)
	semverRE = regexp.MustCompile(`\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?`)
	// Fallback for non-semver strings like "2025.7"
	shortVerRE = regexp.MustCompile(`\d+\.\d+`)
)

func ExtractVersion(s string) string {
	if v := semverRE.FindString(s); v != "" {
		return v
	}
	return shortVerRE.FindString(s)
}
