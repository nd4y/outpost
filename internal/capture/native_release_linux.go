package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

const NativeReleaseFormat = "outpost-native-release-1"
const MaxNativeRelease = 8192
const nativeReleaseFile = "native-release.json"

type NativeReleaseTicket struct {
	Format     string `json:"format"`
	Operation  string `json:"operation"`
	Profile    string `json:"profile"`
	Domain     string `json:"domain"`
	Repository string `json:"repository"`
	Epoch      uint64 `json:"epoch"`
	Sequence   uint64 `json:"sequence"`
	Generation string `json:"generation"`
	Snapshot   string `json:"snapshot"`
	Policy     string `json:"policy"`
	IssuedUnix int64  `json:"issuedUnix"`
	Signature  []byte `json:"signature,omitempty"`
}

type NativeReleaseStatus struct {
	TicketSHA256 string `json:"ticketSHA256"`
	Generation   string `json:"generation"`
	IssuedUnix   int64  `json:"issuedUnix"`
}

func nativeSnapshotName(name string) bool {
	return strings.HasPrefix(name, nativeSnapshotPrefix) && storage.ID(strings.TrimPrefix(name, nativeSnapshotPrefix))
}

func VerifyNativeRelease(raw, manifest []byte, producer PreparedTrust, trust generation.Trust, now time.Time) (NativeReleaseTicket, error) {
	var ticket NativeReleaseTicket
	m, err := VerifyPreparedExport(manifest, producer, now)
	if err != nil || producer.Consistency() != "filesystem" || !nativeSnapshotName(m.Root) || len(trust.Writer) != ed25519.PublicKeySize ||
		storage.Decode(raw, &ticket, MaxNativeRelease) != nil || ticket.Format != NativeReleaseFormat || ticket.Operation != storage.Hash(manifest) ||
		ticket.Profile != producer.Profile || !storage.ID(ticket.Domain) || ticket.Domain != trust.Domain ||
		!storage.ID(ticket.Repository) || ticket.Repository != trust.Repository || ticket.Epoch == 0 || ticket.Epoch != trust.Epoch ||
		ticket.Sequence == 0 || !storage.ID(ticket.Generation) || ticket.Snapshot != m.SnapshotID ||
		ticket.IssuedUnix < m.SnapshotUnix || ticket.IssuedUnix > now.Unix() ||
		(ticket.Policy != "complete-copy" && ticket.Policy != TwoHolderCoverage && ticket.Policy != PairedSplitCoverage) {
		return NativeReleaseTicket{}, ErrInvalid
	}
	canonical, err := json.Marshal(ticket)
	if err != nil || !bytes.Equal(raw, canonical) {
		return NativeReleaseTicket{}, ErrInvalid
	}
	signature := ticket.Signature
	ticket.Signature = nil
	message, err := json.Marshal(ticket)
	if err != nil || !ed25519.Verify(trust.Writer, append([]byte(NativeReleaseFormat+"\x00"), message...), signature) {
		return NativeReleaseTicket{}, ErrInvalid
	}
	ticket.Signature = signature
	return ticket, nil
}

func (j *Job) releaseCommittedView(ctx context.Context, generation, policy string) error {
	operation, view := j.intent.Operation, j.options.Profile.View
	if err := j.options.Provider.Release(ctx, operation, view); err != nil {
		return err
	}
	if provider, ok := j.options.Provider.(*PreparedProvider); ok && provider.o.NativeReleaseTickets {
		return provider.recordNativeRelease(ctx, j.authority.Trust, j.options.Writer, j.intent.Sequence, generation, policy)
	}
	return nil
}

func (p *PreparedProvider) recordNativeRelease(ctx context.Context, trust generation.Trust, key ed25519.PrivateKey, sequence uint64, id, policy string) error {
	return p.store.WithLock(ctx, func() error {
		if err := p.guard(ctx); err != nil {
			return err
		}
		s, err := p.load()
		if err != nil {
			return err
		}
		if !p.o.NativeReleaseTickets || !s.Released || len(key) != ed25519.PrivateKeySize ||
			!bytes.Equal(key.Public().(ed25519.PublicKey), trust.Writer) {
			return ErrInvalid
		}
		raw, err := p.store.Read(nativeReleaseFile)
		if err == nil {
			ticket, err := VerifyNativeRelease(raw, s.Manifest, p.o.Trust, trust, time.Now())
			if err != nil || ticket.Generation != id || ticket.Sequence != sequence || ticket.Policy != policy {
				return ErrInvalid
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		m, err := VerifyPreparedExport(s.Manifest, p.o.Trust, time.Now())
		if err != nil {
			return err
		}
		ticket := NativeReleaseTicket{Format: NativeReleaseFormat, Operation: s.Operation, Profile: p.o.Trust.Profile,
			Domain: trust.Domain, Repository: trust.Repository, Epoch: trust.Epoch, Sequence: sequence, Generation: id,
			Snapshot: m.SnapshotID, Policy: policy, IssuedUnix: time.Now().Unix()}
		unsigned, err := json.Marshal(ticket)
		if err != nil {
			return err
		}
		ticket.Signature = ed25519.Sign(key, append([]byte(NativeReleaseFormat+"\x00"), unsigned...))
		raw, err = json.Marshal(ticket)
		if err != nil {
			return err
		}
		if _, err = VerifyNativeRelease(raw, s.Manifest, p.o.Trust, trust, time.Now()); err != nil {
			return err
		}
		if err = p.guard(ctx); err != nil {
			return err
		}
		if err = p.store.Write(nativeReleaseFile, raw); err != nil {
			return err
		}
		return p.point("native-release-ticket-durable")
	})
}

func (p *PreparedProvider) NativeRelease(ctx context.Context, trust generation.Trust) ([]byte, *NativeReleaseStatus, error) {
	if !p.o.NativeReleaseTickets {
		return nil, nil, ErrInvalid
	}
	var raw []byte
	var status *NativeReleaseStatus
	err := p.store.WithLock(ctx, func() error {
		if err := p.guard(ctx); err != nil {
			return err
		}
		s, err := p.load()
		if err != nil || !s.Released {
			return err
		}
		raw, err = p.store.Read(nativeReleaseFile)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		ticket, err := VerifyNativeRelease(raw, s.Manifest, p.o.Trust, trust, time.Now())
		if err != nil {
			return err
		}
		status = &NativeReleaseStatus{TicketSHA256: storage.Hash(raw), Generation: ticket.Generation, IssuedUnix: ticket.IssuedUnix}
		return nil
	})
	return raw, status, err
}
