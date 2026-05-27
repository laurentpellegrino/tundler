// Package register is the per-provider blank-import home. Each
// provider has its own tagged file (register_<provider>.go with
// `//go:build provider_<provider>`) so a `go build
// -tags provider_<name>` only links that provider into the final
// binary — and only that provider's go:embed'd data (e.g.
// protonvpn's servers.json) ends up baked in. This keeps every
// other provider image free of data it doesn't need.
//
// This file carries no tag so `go vet ./...` / `go test ./...`
// / `go build ./...` without -tags keep working from local dev.
// In that no-tag mode the binary has no providers registered;
// the runtime fails at first Connect() with a clear "unknown
// provider" error rather than a compile failure.
package register
