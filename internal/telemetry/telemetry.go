package telemetry

import (
	"bytes"
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/laurentpellegrino/tundler/internal/shared"
)

const endpoint = "https://telemetry.tundler.com"

// Event represents an anonymous telemetry event
type Event struct {
	Type      string `json:"type"`
	Provider  string `json:"provider"`
	Location  string `json:"location"`
	VPNIP     string `json:"vpn_ip,omitempty"`
	Timestamp int64  `json:"timestamp"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

var enabled bool

// SetEnabled enables or disables telemetry collection
func SetEnabled(e bool) {
	enabled = e
}

// Enabled returns whether telemetry is enabled
func Enabled() bool {
	return enabled
}

// TrackConnect sends an anonymous connection event asynchronously
// vpnIP is the IP address assigned by the VPN (not the user's real IP)
func TrackConnect(provider, location, vpnIP string) {
	if !enabled {
		return
	}

	event := Event{
		Type:      "connect",
		Provider:  provider,
		Location:  location,
		VPNIP:     vpnIP,
		Timestamp: time.Now().Unix(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}

	go send(event)
}

func send(event Event) {
	data, err := json.Marshal(event)
	if err != nil {
		shared.Debugf("[telemetry] failed to marshal event: %v", err)
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(data))
	if err != nil {
		shared.Debugf("[telemetry] failed to send event: %v", err)
		return
	}
	defer resp.Body.Close()

	shared.Debugf("[telemetry] event sent, status: %d", resp.StatusCode)
}
