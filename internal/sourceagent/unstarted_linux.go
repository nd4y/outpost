package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/storage"
)

const UnstartedRetirementFormat = "outpost-source-unstarted-retirement-1"
const MaxUnstartedRetirement = 4096

// UnstartedRetirement authorizes one local state transition before the durable
// ACTIVE fence. It carries no authority to resume an expired capture or clean up.
type UnstartedRetirement struct {
	Format            string `json:"format"`
	Source            string `json:"source"`
	Operation         string `json:"operation"`
	Authority         string `json:"authority"`
	Intent            string `json:"intent"`
	Checkpoint        string `json:"checkpoint"`
	IntentExpiresUnix int64  `json:"intentExpiresUnix"`
	NotBefore         int64  `json:"notBefore"`
	ExpiresUnix       int64  `json:"expiresUnix"`
	Signature         []byte `json:"signature,omitempty"`
}

func (g UnstartedRetirement) valid(now int64) bool {
	return g.Format == UnstartedRetirementFormat && storage.ID(g.Source) && storage.ID(g.Operation) &&
		storage.ID(g.Authority) && storage.ID(g.Intent) && storage.ID(g.Checkpoint) && g.IntentExpiresUnix > 0 &&
		g.IntentExpiresUnix <= g.NotBefore && g.NotBefore <= now && now < g.ExpiresUnix &&
		g.ExpiresUnix <= 1<<40 && g.ExpiresUnix-g.NotBefore <= 24*3600
}

func (g UnstartedRetirement) unsigned() []byte {
	g.Signature = nil
	raw, _ := json.Marshal(g)
	return append([]byte(UnstartedRetirementFormat+"\x00"), raw...)
}

func SignUnstartedRetirement(g UnstartedRetirement, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || len(g.Signature) != 0 || !g.valid(now.Unix()) {
		return nil, ErrInvalid
	}
	g.Signature = ed25519.Sign(key, g.unsigned())
	return json.Marshal(g)
}

func (a *Agent) unstartedRetirement(s state, i ingress.Intent, start, end int64) UnstartedRetirement {
	return UnstartedRetirement{Format: UnstartedRetirementFormat, Source: i.Source, Operation: i.Operation,
		Authority: storage.Hash(a.intentAuthority(s)), Intent: storage.Hash(s.Intent), Checkpoint: storage.Hash(s.Checkpoint),
		IntentExpiresUnix: i.ExpiresUnix, NotBefore: start, ExpiresUnix: end}
}

func (a *Agent) UnstartedRetirementPreview(ctx context.Context) (UnstartedRetirement, error) {
	var out UnstartedRetirement
	err := a.lease.WithLock(ctx, func() error {
		if err := a.guard(ctx); err != nil {
			return err
		}
		s, err := a.load()
		if err != nil {
			return err
		}
		if s.Phase != "PREPARING" {
			return ErrInvalid
		}
		i, err := a.stateIntent(s)
		now := time.Now().Unix()
		if err != nil || now < i.ExpiresUnix {
			return ErrInvalid
		}
		out = a.unstartedRetirement(s, i, now, now+600)
		return nil
	})
	return out, err
}

type unstartedArchive struct {
	Authority    []byte          `json:"authority"`
	Intent       []byte          `json:"intent"`
	Grant        json.RawMessage `json:"grant"`
	RecordedUnix int64           `json:"recordedUnix"`
	Signature    []byte          `json:"signature,omitempty"`
}

func (r unstartedArchive) unsigned() []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte(UnstartedRetirementFormat+"/archive\x00"), raw...)
}

func (a *Agent) verifyUnstartedRetirement(raw []byte, s state, i ingress.Intent, now int64) bool {
	var g UnstartedRetirement
	if storage.Decode(raw, &g, MaxUnstartedRetirement) != nil || !g.valid(now) ||
		!ed25519.Verify(a.b.Local.Owner, g.unsigned(), g.Signature) {
		return false
	}
	want := a.unstartedRetirement(s, i, g.NotBefore, g.ExpiresUnix)
	return bytes.Equal(g.unsigned(), want.unsigned())
}

func (a *Agent) readUnstartedArchive(s state, i ingress.Intent, digest string) (unstartedArchive, error) {
	var r unstartedArchive
	if !storage.ID(digest) {
		return r, ErrInvalid
	}
	raw, err := a.store.Read("unstarted-" + digest + ".json")
	if err != nil {
		return r, err
	}
	if storage.Decode(raw, &r, maxState) != nil || storage.Hash(r.Grant) != digest || r.RecordedUnix > time.Now().Unix() ||
		!bytes.Equal(r.Authority, a.intentAuthority(s)) || !bytes.Equal(r.Intent, s.Intent) ||
		!a.verifyUnstartedRetirement(r.Grant, s, i, r.RecordedUnix) ||
		!ed25519.Verify(a.anchor.Trust.Writer, r.unsigned(), r.Signature) {
		return r, ErrInvalid
	}
	return r, nil
}

// RetireUnstarted uses the same lease as Prepare, Next and Run. The normal
// agent persists ACTIVE before calling Job.Run, even when Begin may fail.
func (a *Agent) RetireUnstarted(ctx context.Context, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxUnstartedRetirement {
		return ErrInvalid
	}
	raw = bytes.Clone(raw)
	return a.lease.WithLock(ctx, func() error {
		if err := a.guard(ctx); err != nil {
			return err
		}
		s, err := a.load()
		if err != nil {
			return err
		}
		if s.Phase != "PREPARING" && s.Phase != "ABANDONED" {
			return ErrInvalid
		}
		i, err := a.stateIntent(s)
		now := time.Now().Unix()
		if err != nil || !a.verifyUnstartedRetirement(raw, s, i, now) {
			return ErrInvalid
		}
		digest := storage.Hash(raw)
		if s.Phase == "ABANDONED" {
			if s.Retirement != digest {
				return ingress.ErrConflict
			}
			return nil
		}
		_, err = a.readUnstartedArchive(s, i, digest)
		if errors.Is(err, os.ErrNotExist) {
			record := unstartedArchive{Authority: a.intentAuthority(s), Intent: s.Intent, Grant: raw, RecordedUnix: now}
			record.Signature = ed25519.Sign(a.writer, record.unsigned())
			encoded, err := json.Marshal(record)
			if err != nil {
				return err
			}
			if err = a.store.Write("unstarted-"+digest+".json", encoded); err != nil {
				return err
			}
			if err = a.point("source-unstarted-retirement-durable"); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if err = a.guard(ctx); err != nil {
			return err
		}
		if err = a.point("source-unstarted-before-state"); err != nil {
			return err
		}
		if !a.verifyUnstartedRetirement(raw, s, i, time.Now().Unix()) {
			return ErrInvalid
		}
		s.Phase, s.Retirement = "ABANDONED", digest
		return a.save(s)
	})
}
