package main

import (
	"context"
	"errors"
	"os"
	"testing"
)

// TestMain keeps the late exit-IP lookup off the network: a test tunnel
// that comes up without an exit IP would otherwise probe the public
// egress endpoint from the machine running the tests.
func TestMain(m *testing.M) {
	probeExitForBackfill = func(context.Context) (string, error) {
		return "", errors.New("egress probe disabled in tests")
	}
	os.Exit(m.Run())
}
