package manager

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestDropMalformedLocations(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "express CLI timeout output gets the numeric fragment dropped",
			in:   []string{"Timed", "out", "after", "5.002", "sec"},
			want: []string{"Timed", "out", "after", "sec"},
		},
		{
			name: "real express region slugs (hyphens, parens, digits, dots) all kept",
			in: []string{
				"smart",
				"uk-london",
				"australia-sydney-2",
				"india-(via-singapore)",
				"usa-st.-louis",
			},
			want: []string{
				"smart",
				"uk-london",
				"australia-sydney-2",
				"india-(via-singapore)",
				"usa-st.-louis",
			},
		},
		{
			name: "nord underscored countries kept",
			in:   []string{"Cayman_Islands", "Lao_Peoples_Democratic_Republic"},
			want: []string{"Cayman_Islands", "Lao_Peoples_Democratic_Republic"},
		},
		{
			name: "proton spaced/apostrophed names kept",
			in:   []string{"Costa Rica", "Cote d'Ivoire", "Korea"},
			want: []string{"Costa Rica", "Cote d'Ivoire", "Korea"},
		},
		{
			name: "empty strings dropped",
			in:   []string{"", "albania", "", "germany-berlin"},
			want: []string{"albania", "germany-berlin"},
		},
		{
			name: "purely numeric tokens dropped (CLI artifact)",
			in:   []string{"5", "5.002", "1.0.0", "real-region", "0"},
			want: []string{"real-region"},
		},
		{
			name: "empty input returned as-is",
			in:   nil,
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dropMalformedLocations(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("dropMalformedLocations(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// newTestManager builds a Manager with a controllable clock so cooldown
// expiry can be exercised without time.Sleep. Providers map is empty —
// the cooldown helpers don't read it.
func newTestManager() (*Manager, *time.Time) {
	clock := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	m := &Manager{
		recentFailures: map[string]time.Time{},
	}
	m.now = func() time.Time { return clock }
	return m, &clock
}

func TestDropCooldown_KeepsLocationsWithoutFailures(t *testing.T) {
	m, _ := newTestManager()
	in := []string{"Bermuda", "Jersey", "Mexico"}
	got := m.dropCooldown("nordvpn", in)
	if !reflect.DeepEqual(got, in) {
		t.Errorf("dropCooldown without prior failures = %v, want %v", got, in)
	}
}

func TestDropCooldown_SkipsRecentlyFailed(t *testing.T) {
	m, _ := newTestManager()
	m.markConnectFailure("nordvpn", "Bermuda")
	got := m.dropCooldown("nordvpn", []string{"Bermuda", "Jersey", "Mexico"})
	want := []string{"Jersey", "Mexico"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dropCooldown after failing Bermuda = %v, want %v", got, want)
	}
}

func TestDropCooldown_IsScopedPerProvider(t *testing.T) {
	m, _ := newTestManager()
	// Mexico failing on surfshark must not affect nordvpn — different
	// exit-IP pools, different reasons, different cooldowns.
	m.markConnectFailure("surfshark", "Mexico")
	got := m.dropCooldown("nordvpn", []string{"Mexico", "Bermuda"})
	want := []string{"Mexico", "Bermuda"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("nordvpn pick after surfshark Mexico failure = %v, want %v", got, want)
	}
}

func TestDropCooldown_ExpiresAfterWindow(t *testing.T) {
	m, clock := newTestManager()
	m.markConnectFailure("nordvpn", "Bermuda")

	// Just before the cooldown window closes, still suppressed.
	*clock = clock.Add(failureCooldown - time.Second)
	if got := m.dropCooldown("nordvpn", []string{"Bermuda"}); len(got) != 0 {
		t.Errorf("dropCooldown 1s before expiry = %v, want empty", got)
	}

	// At/after the window, the pair must come back AND the entry must
	// be pruned from the map (lazy cleanup).
	*clock = clock.Add(time.Second)
	got := m.dropCooldown("nordvpn", []string{"Bermuda"})
	if !reflect.DeepEqual(got, []string{"Bermuda"}) {
		t.Errorf("dropCooldown at expiry = %v, want [Bermuda]", got)
	}
	if _, stillTracked := m.recentFailures["nordvpn\x00Bermuda"]; stillTracked {
		t.Errorf("expired entry was not pruned from recentFailures")
	}
}

func TestDropCooldown_HandlesEmptyInput(t *testing.T) {
	m, _ := newTestManager()
	if got := m.dropCooldown("nordvpn", nil); got != nil {
		t.Errorf("dropCooldown(nil) = %v, want nil", got)
	}
	if got := m.dropCooldown("nordvpn", []string{}); len(got) != 0 {
		t.Errorf("dropCooldown([]) = %v, want empty", got)
	}
}

func TestMarkConnectFailure_IgnoresEmptyLocation(t *testing.T) {
	m, _ := newTestManager()
	m.markConnectFailure("nordvpn", "")
	if len(m.recentFailures) != 0 {
		t.Errorf("markConnectFailure with empty location recorded an entry: %v", m.recentFailures)
	}
}

// Sanity: cooldown filter combines correctly with the malformed filter.
// Callers run dropMalformedLocations first, then dropCooldown — both
// should be order-stable so callers can compose them without surprises.
func TestCooldownAndMalformedFiltersCompose(t *testing.T) {
	m, _ := newTestManager()
	m.markConnectFailure("expressvpn", "usa-los-angeles-1")

	in := []string{"5.002", "uk-london", "usa-los-angeles-1", "germany-berlin"}
	got := dropMalformedLocations(in)
	got = m.dropCooldown("expressvpn", got)
	want := []string{"uk-london", "germany-berlin"}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("composed filters = %v, want %v", got, want)
	}
}

func TestIsPurelyNumeric(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"5.002", true},
		{"5", true},
		{"1.0.0", true},
		{"0", true},
		{"", false}, // empty handled separately by caller
		{"5a", false},
		{"a5", false},
		{"5.0a", false},
		{"usa-st.-louis", false},
		{"australia-sydney-2", false},
	}
	for _, tc := range cases {
		if got := isPurelyNumeric(tc.in); got != tc.want {
			t.Errorf("isPurelyNumeric(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
