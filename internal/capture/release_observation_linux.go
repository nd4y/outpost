package capture

import (
	"encoding/json"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

type releaseObservation struct {
	ViewDigest   string `json:"viewDigest"`
	ObservedUnix int64  `json:"observedUnix"`
}

func releaseObservationName(operation string) string {
	return "source-release-" + operation + ".json"
}

// Called once, after the provider's view.json release has committed. Missing
// telemetry must never prevent release or block a resumed backup.
func recordReleaseObservation(parent *os.Root, operation string, provider *statefile.Store, admit statefile.Admission) {
	if admit == nil {
		return
	}
	view, err := provider.Read("view.json")
	if err != nil {
		return
	}
	raw, _ := json.Marshal(releaseObservation{ViewDigest: storage.Hash(view), ObservedUnix: time.Now().Unix()})
	name := releaseObservationName(operation)
	_ = statefile.Guard(admit, name, len(raw), func() error {
		store, err := statefile.OpenAt(parent, "telemetry", 4096, true)
		if err != nil {
			return err
		}
		defer store.Close()
		return store.Write(name, raw)
	})
}

// ProviderReleaseObservedUnix reads optional, local timing evidence. It never
// synthesizes a time for old journals, failed telemetry or uncertain writes.
func ProviderReleaseObservedUnix(parent *os.Root, operation, directory string) int64 {
	if !storage.ID(operation) {
		return 0
	}
	store, err := statefile.OpenAt(parent, "telemetry", 4096, false)
	if err != nil {
		return 0
	}
	defer store.Close()
	raw, err := store.Read(releaseObservationName(operation))
	var record releaseObservation
	if err != nil || storage.Decode(raw, &record, 4096) != nil || !storage.ID(record.ViewDigest) ||
		record.ObservedUnix <= 0 || record.ObservedUnix > time.Now().Unix() {
		return 0
	}
	provider, err := statefile.OpenAt(parent, directory, MaxPreparedExport+8192, false)
	if err != nil {
		return 0
	}
	defer provider.Close()
	view, err := provider.Read("view.json")
	var state struct {
		Released bool `json:"released"`
	}
	if err != nil || storage.Hash(view) != record.ViewDigest || json.Unmarshal(view, &state) != nil || !state.Released {
		return 0
	}
	return record.ObservedUnix
}
