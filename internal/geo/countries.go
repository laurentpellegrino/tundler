// Package geo is tundler's single source of country knowledge: one
// canonical ISO-3166-1 alpha-2 table, tolerant name/code lookup, and the
// epoch-seeded country ordering used by the fleet's soft region-spread
// preference (cmd/tundler-tunnel/preference.go).
//
// It replaces the two private, near-identical code→name tables that used
// to live in the fastvpn and ipvanish provider packages. Keeping the
// table here means every provider's location vocabulary — "Germany",
// "de", "DE", "de-berlin", "United_States" — funnels through the same
// normalization (see GuessAlpha2 in normalize.go), which is what makes
// cross-provider region comparison possible at all.
//
// The table is deliberately NOT the full 249-entry ISO registry: it is
// the union of the countries commercial VPN catalogs actually offer.
// A country missing from the table simply cannot be *preferred* by the
// region-spread walk — it remains fully connectable — so extending the
// table is always safe and never urgent.
package geo

import (
	"sort"
	"strings"
)

// countryNames maps ISO-3166-1 alpha-2 codes to canonical English
// country names. Keys are real ISO codes: "GB", not the "UK" that
// several provider catalogs use — codeAliases translates those on
// lookup.
var countryNames = map[string]string{
	"AD": "Andorra",
	"AE": "United Arab Emirates",
	"AF": "Afghanistan",
	"AL": "Albania",
	"AM": "Armenia",
	"AO": "Angola",
	"AR": "Argentina",
	"AT": "Austria",
	"AU": "Australia",
	"AZ": "Azerbaijan",
	"BA": "Bosnia and Herzegovina",
	"BD": "Bangladesh",
	"BE": "Belgium",
	"BG": "Bulgaria",
	"BH": "Bahrain",
	"BM": "Bermuda",
	"BN": "Brunei",
	"BO": "Bolivia",
	"BR": "Brazil",
	"BS": "Bahamas",
	"BT": "Bhutan",
	"BW": "Botswana",
	"BY": "Belarus",
	"BZ": "Belize",
	"CA": "Canada",
	"CD": "DR Congo",
	"CH": "Switzerland",
	"CI": "Ivory Coast",
	"CL": "Chile",
	"CM": "Cameroon",
	"CO": "Colombia",
	"CR": "Costa Rica",
	"CU": "Cuba",
	"CY": "Cyprus",
	"CZ": "Czech Republic",
	"DE": "Germany",
	"DK": "Denmark",
	"DO": "Dominican Republic",
	"DZ": "Algeria",
	"EC": "Ecuador",
	"EE": "Estonia",
	"EG": "Egypt",
	"ES": "Spain",
	"ET": "Ethiopia",
	"FI": "Finland",
	"FJ": "Fiji",
	"FR": "France",
	"GE": "Georgia",
	"GG": "Guernsey",
	"GH": "Ghana",
	"GI": "Gibraltar",
	"GL": "Greenland",
	"GR": "Greece",
	"GT": "Guatemala",
	"HK": "Hong Kong",
	"HN": "Honduras",
	"HR": "Croatia",
	"HT": "Haiti",
	"HU": "Hungary",
	"ID": "Indonesia",
	"IE": "Ireland",
	"IL": "Israel",
	"IM": "Isle of Man",
	"IN": "India",
	"IQ": "Iraq",
	"IS": "Iceland",
	"IT": "Italy",
	"JE": "Jersey",
	"JM": "Jamaica",
	"JO": "Jordan",
	"JP": "Japan",
	"KE": "Kenya",
	"KG": "Kyrgyzstan",
	"KH": "Cambodia",
	"KR": "South Korea",
	"KW": "Kuwait",
	"KY": "Cayman Islands",
	"KZ": "Kazakhstan",
	"LA": "Laos",
	"LB": "Lebanon",
	"LI": "Liechtenstein",
	"LK": "Sri Lanka",
	"LT": "Lithuania",
	"LU": "Luxembourg",
	"LV": "Latvia",
	"LY": "Libya",
	"MA": "Morocco",
	"MC": "Monaco",
	"MD": "Moldova",
	"ME": "Montenegro",
	"MK": "North Macedonia",
	"MM": "Myanmar",
	"MN": "Mongolia",
	"MO": "Macao",
	"MT": "Malta",
	"MU": "Mauritius",
	"MV": "Maldives",
	"MX": "Mexico",
	"MY": "Malaysia",
	"MZ": "Mozambique",
	"NG": "Nigeria",
	"NI": "Nicaragua",
	"NL": "Netherlands",
	"NO": "Norway",
	"NP": "Nepal",
	"NZ": "New Zealand",
	"OM": "Oman",
	"PA": "Panama",
	"PE": "Peru",
	"PG": "Papua New Guinea",
	"PH": "Philippines",
	"PK": "Pakistan",
	"PL": "Poland",
	"PR": "Puerto Rico",
	"PT": "Portugal",
	"PY": "Paraguay",
	"QA": "Qatar",
	"RO": "Romania",
	"RS": "Serbia",
	"RU": "Russia",
	"RW": "Rwanda",
	"SA": "Saudi Arabia",
	"SE": "Sweden",
	"SG": "Singapore",
	"SI": "Slovenia",
	"SK": "Slovakia",
	"SN": "Senegal",
	"SV": "El Salvador",
	"TH": "Thailand",
	"TN": "Tunisia",
	"TR": "Turkey",
	"TT": "Trinidad and Tobago",
	"TW": "Taiwan",
	"TZ": "Tanzania",
	"UA": "Ukraine",
	"UG": "Uganda",
	"US": "United States",
	"UY": "Uruguay",
	"UZ": "Uzbekistan",
	"VE": "Venezuela",
	"VN": "Vietnam",
	"YE": "Yemen",
	"ZA": "South Africa",
	"ZM": "Zambia",
	"ZW": "Zimbabwe",

	"GB": "United Kingdom",
}

// codeAliases maps the non-ISO codes seen in real provider catalogs to
// their ISO equivalent. FastVPN, IPVanish and PIA all say "UK"; nobody
// says "GB".
var codeAliases = map[string]string{
	"UK": "GB",
}

// nameAliases maps normalized (see normalizeName) country-name variants
// seen in provider catalogs to their alpha-2 code. Canonical names from
// countryNames are indexed automatically — only spellings that DIFFER
// from the canonical name belong here.
var nameAliases = map[string]string{
	"bosnia":                          "BA",
	"brunei darussalam":               "BN",
	"burma":                           "MM",
	"cote divoire":                    "CI", // apostrophes stripped by normalizeName
	"czechia":                         "CZ",
	"great britain":                   "GB",
	"korea":                           "KR",
	"lao peoples democratic republic": "LA",
	"macau":                           "MO",
	"macedonia":                       "MK",
	"republic of korea":               "KR",
	"republic of moldova":             "MD",
	"russian federation":              "RU",
	"turkiye":                         "TR",
	"uae":                             "AE",
	"uk":                              "GB",
	"united states of america":        "US",
	"usa":                             "US",
	"viet nam":                        "VN",
}

// nameIndex is the merged normalized-name → alpha-2 lookup, built once
// from countryNames + nameAliases.
var nameIndex = func() map[string]string {
	idx := make(map[string]string, len(countryNames)+len(nameAliases))
	for code, name := range countryNames {
		idx[normalizeName(name)] = code
	}
	for name, code := range nameAliases {
		idx[name] = code
	}
	return idx
}()

// normalizeName lowercases, converts underscores and hyphens to
// spaces, strips apostrophes and periods, and collapses whitespace —
// the minimal canonical form that makes "United_States", "united
// states", "czech-republic" and "Lao_Peoples_Democratic_Republic" all
// comparable. The index is built through the same function, so a
// hyphenated canonical name would still resolve.
func normalizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", " ")
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.ReplaceAll(name, "'", "")
	name = strings.ReplaceAll(name, "’", "")
	name = strings.ReplaceAll(name, ".", "")
	return strings.Join(strings.Fields(name), " ")
}

// CountryName returns the canonical English name for an alpha-2 code
// (code aliases like "UK" are accepted). ok=false for unknown codes.
func CountryName(alpha2 string) (string, bool) {
	code := strings.ToUpper(strings.TrimSpace(alpha2))
	if iso, ok := codeAliases[code]; ok {
		code = iso
	}
	n, ok := countryNames[code]
	return n, ok
}

// Alpha2FromName resolves a country name (any case, underscores or
// hyphens for spaces, apostrophes optional) to its alpha-2 code. ok=false when the
// name is unknown.
func Alpha2FromName(name string) (string, bool) {
	code, ok := nameIndex[normalizeName(name)]
	return code, ok
}

// AllAlpha2 returns every known alpha-2 code, sorted — the universe the
// region-spread preference permutes each epoch. The slice is freshly
// allocated; callers may mutate it.
func AllAlpha2() []string {
	codes := make([]string, 0, len(countryNames))
	for code := range countryNames {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes
}
