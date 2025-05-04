package shared

import "regexp"

// Full “semver” (x.y.z, optional -prerelease and +build)
var semverRE = regexp.MustCompile(`\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?`)

func ExtractVersion(s string) string { return semverRE.FindString(s) }
