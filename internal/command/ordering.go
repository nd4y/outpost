package command

import "github.com/nd4y/outpost/internal/storage"

// Controls have an independent replay fence so a later pause can overtake work
// without making an earlier, not yet delivered work command stale.
func Control(kind string) bool { return kind == "pause" || kind == "resume" }

// Scheduled commands run on the worker execution lease.
func Scheduled(kind string) bool { return oneOf(kind, "scrub", "maintenance", "restore", "retention") }

func SequenceScope(service, kind string) string {
	if Control(kind) {
		return service
	}
	return storage.Hash([]byte("outpost-command-work-sequence-1\x00" + service))
}

// Position is internal cursor order. Original on-wire sequence numbers remain
// within the interoperable integer range; cursors encode this value as text.
func Position(sequence uint64, kind string) uint64 {
	if Control(kind) {
		return sequence
	}
	return sequence | (uint64(1) << 63)
}
func ValidPosition(position uint64) bool {
	sequence := position & ^(uint64(1) << 63)
	return position == 0 || sequence > 0 && sequence <= MaxSafeInteger
}
