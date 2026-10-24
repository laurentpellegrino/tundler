package hidemyass

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type savedDevice struct {
	AccountHash string         `json:"account_hash"`
	Fingerprint string         `json:"fingerprint"`
	Session     deviceSession  `json:"session"`
	Credentials vpnCredentials `json:"credentials"`
}

func stateDir() string {
	if dir := os.Getenv("HIDEMYASS_STATE_DIR"); dir != "" {
		return dir
	}
	return "/var/lib/tundler/hidemyass"
}

func accountHash(username, password string) string {
	sum := sha256.Sum256([]byte(username + "\x00" + password))
	return hex.EncodeToString(sum[:])
}

// The server associates the same fingerprint with the same device. A pod must
// keep its identity across reauthentication and image/container restarts.
func deviceFingerprint(username string) string {
	if id := os.Getenv("HIDEMYASS_DEVICE_ID"); id != "" {
		return id
	}
	pod := os.Getenv("POD_NAME")
	if pod == "" {
		pod, _ = os.Hostname()
	}
	sum := sha256.Sum256([]byte(username + "\x00" + pod))
	return "tundler-" + hex.EncodeToString(sum[:16])
}

func ensurePrivateDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("create HMA private directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("HMA state directory must be a private directory (mode 0700)")
	}
	return nil
}

func writePrivate(path string, data []byte) error {
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".hma-*")
	if err != nil {
		return errors.New("create HMA state file")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("write HMA state file")
	}
	if os.Rename(tmp, path) != nil {
		return errors.New("install HMA state file")
	}
	return nil
}

func loadDevice(dir, hash, fingerprint string) (savedDevice, bool) {
	path := filepath.Join(dir, "device.json")
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return savedDevice{}, false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return savedDevice{}, false
	}
	if info.Size() > maxAPIResponse {
		return savedDevice{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return savedDevice{}, false
	}
	var saved savedDevice
	if json.Unmarshal(raw, &saved) != nil || saved.AccountHash != hash || saved.Fingerprint != fingerprint || saved.Session.UDID == "" || (saved.Credentials.DeviceUDID != "" && saved.Credentials.DeviceUDID != saved.Session.UDID) {
		return savedDevice{}, false
	}
	return saved, true
}

func saveDevice(dir string, saved savedDevice) error {
	raw, err := json.Marshal(saved)
	if err != nil {
		return errors.New("encode HMA device state")
	}
	return writePrivate(filepath.Join(dir, "device.json"), raw)
}

func supportedLocation(country locationCountry) bool {
	return strings.EqualFold(country.State, "active") && country.Key != ""
}
