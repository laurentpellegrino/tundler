package geo

import (
	"math/rand/v2"
	"time"
)

// EpochLength is how long one fleet-shared country ordering stays
// valid. Rationale for 24h: pods rotate at uncoordinated random times
// (2-4h windows by default), so ANY epoch boundary momentarily lets two
// pods compute different orderings and land on the same country. That
// is acceptable — the whole layer is a soft preference — so we optimize
// for simplicity: a calendar-day epoch means all pods share one
// ordering for ~6-12 rotations (their fleet-slot offsets keep them
// apart), and tomorrow explores a fresh permutation. Anything fancier
// (rotation-count-coupled epochs, persisted cursors) buys marginal
// collision avoidance for real coordination cost.
const EpochLength = 24 * time.Hour

// Epoch returns the preference epoch containing now.
func Epoch(now time.Time) uint64 {
	return uint64(now.Unix()) / uint64(EpochLength/time.Second)
}

// preferredOrderSeed keeps the epoch shuffle stable across binaries:
// every pod in the fleet MUST derive the identical permutation for a
// given epoch or the even-spread offsets stop meaning anything.
const preferredOrderSeed = 0x74756e646c6572 // "tundler"

// PreferredOrder returns the epoch's fleet-shared permutation of
// AllAlpha2(): a deterministic shuffle seeded only by the epoch, so
// every pod computes the same ordering with zero coordination. The
// slice is freshly allocated; callers may consume it destructively.
func PreferredOrder(epoch uint64) []string {
	codes := AllAlpha2()
	r := rand.New(rand.NewPCG(epoch, preferredOrderSeed))
	r.Shuffle(len(codes), func(i, j int) { codes[i], codes[j] = codes[j], codes[i] })
	return codes
}
