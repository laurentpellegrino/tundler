package shared

import (
	"net/http"
	"strings"
)

// Error is a typed application error serialised to JSON by the HTTP layer.
type Error struct {
	Code    string `json:"code"`    // ALWAYS UPPERCASE
	Message string `json:"message"` // human-readable
	Status  int    `json:"-"`       // HTTP status (not serialised)
}

func (e Error) Error() string { return e.Message }

// New creates an upper-case coded error.
func New(code, msg string, status int) Error {
	return Error{Code: strings.ToUpper(code), Message: msg, Status: status}
}

var (
	ErrProviderNotLoggedIn = New("PROVIDER_NOT_LOGGED_IN",
		"You need to login in with the specified provider first.", http.StatusFailedDependency) // 424

	ErrNoLoggedInProviders = New("NO_LOGGED_IN_PROVIDERS",
		"You need to login with a provider.", http.StatusFailedDependency) // 424

	ErrUnknownProvider = New("UNKNOWN_PROVIDER",
		"Unknown VPN provider", http.StatusBadRequest) // 400
)
