package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/storage"
)

const observationWindowFormat = "outpost-observation-window-1"

type observationWindowState struct {
	Format      string `json:"format"`
	Scope       string `json:"scope"`
	Binding     string `json:"binding"`
	Window      string `json:"window"`
	StartedUnix int64  `json:"startedUnix"`
}

func observationWindowID(binding string, started int64) string {
	return storage.Hash([]byte(observationWindowFormat + "/" + binding + "/" + strconv.FormatInt(started, 10)))
}
func (w *Worker) observationWindow(ctx context.Context, grant []byte, g observation.Grant, id string, previous []byte, now time.Time) (string, error) {
	scope := storage.Hash([]byte(storage.Hash(grant) + "/" + id + "/" + w.node))
	binding := storage.Hash([]byte(scope + "/" + storage.Hash(previous)))
	name := "observation-window-" + scope + ".json"
	var s observationWindowState
	e := w.state.WithLock(ctx, func() error {
		raw, e := w.state.Read(name)
		missing := errors.Is(e, os.ErrNotExist)
		if !missing {
			if e != nil {
				return e
			}
			if storage.Decode(raw, &s, 4096) != nil || s.Format != observationWindowFormat || s.Scope != scope || !storage.ID(s.Binding) || s.StartedUnix < 1 || s.StartedUnix > now.Unix() || s.Window != observationWindowID(s.Binding, s.StartedUnix) {
				return ErrDenied
			}
		}
		if missing || s.Binding != binding || now.Unix()-s.StartedUnix > g.MaxAgeSeconds {
			s = observationWindowState{observationWindowFormat, scope, binding, observationWindowID(binding, now.Unix()), now.Unix()}
			raw, e = json.Marshal(s)
			if e != nil {
				return e
			}
			return w.state.Write(name, raw)
		}
		return nil
	})
	return s.Window, e
}
