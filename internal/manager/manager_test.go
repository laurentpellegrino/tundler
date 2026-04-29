package manager

import (
	"reflect"
	"testing"
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
