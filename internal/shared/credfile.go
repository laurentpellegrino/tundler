package shared

import (
	"os"
	"path/filepath"
)

// WriteUserPassFile writes an OpenVPN auth-user-pass credentials file
// ("user\npass\n", 0600, parent dir created 0700) and returns its path.
// One helper instead of the six identical per-provider writeCredentials
// copies it replaced — every OpenVPN-direct provider points its
// rewritten `auth-user-pass <file>` directive at the result.
func WriteUserPassFile(dir, filename, user, pass string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(user+"\n"+pass+"\n"), 0o600); err != nil {
		return "", err
	}
	return path, nil
}
