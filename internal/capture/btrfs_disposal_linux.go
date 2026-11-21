package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"time"
	"unsafe"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

const NativeDisposalFormat = "outpost-btrfs-disposal-1"

type NativeDisposalReceipt struct {
	Format         string `json:"format"`
	Binding        string `json:"binding"`
	TicketSHA256   string `json:"ticketSHA256"`
	Operation      string `json:"operation"`
	Snapshot       string `json:"snapshot"`
	Subvolume      uint64 `json:"subvolume"`
	IntentUnix     int64  `json:"intentUnix"`
	RemovedUnix    int64  `json:"removedUnix,omitempty"`
	PathAbsentUnix int64  `json:"pathAbsentUnix,omitempty"`
	Signature      []byte `json:"signature,omitempty"`
}

func deleteNativeSnapshot(parent *os.File, subvolume uint64) error {
	const snapshotDestroyV2 = 0x5000943f
	const byID = 1 << 4
	var args [4096]byte
	binary.NativeEndian.PutUint64(args[16:24], byID)
	binary.NativeEndian.PutUint64(args[56:64], subvolume)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, parent.Fd(), snapshotDestroyV2, uintptr(unsafe.Pointer(&args[0]))); e != 0 {
		return e
	}
	return nil
}

func verifyNativeDisposal(raw []byte, expected NativeDisposalReceipt, producer ed25519.PublicKey, minimum, now int64) (NativeDisposalReceipt, error) {
	var r NativeDisposalReceipt
	if storage.Decode(raw, &r, MaxNativeRelease) != nil || r.Format != NativeDisposalFormat ||
		r.Binding != expected.Binding || r.TicketSHA256 != expected.TicketSHA256 || r.Operation != expected.Operation ||
		r.Snapshot != expected.Snapshot || r.Subvolume < 256 || r.IntentUnix < minimum || r.IntentUnix > now ||
		(r.PathAbsentUnix != 0 && (r.PathAbsentUnix < r.IntentUnix || r.PathAbsentUnix > now)) ||
		(r.RemovedUnix != 0 && (r.RemovedUnix < r.IntentUnix || r.RemovedUnix > r.PathAbsentUnix)) {
		return NativeDisposalReceipt{}, ErrInvalid
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return NativeDisposalReceipt{}, ErrInvalid
	}
	signature := r.Signature
	r.Signature = nil
	body, err := json.Marshal(r)
	if err != nil || !ed25519.Verify(producer, append([]byte(NativeDisposalFormat+"\x00"), body...), signature) {
		return NativeDisposalReceipt{}, ErrInvalid
	}
	r.Signature = signature
	return r, nil
}

func DisposeBtrfsSnapshot(ctx context.Context, p BtrfsProducerProfile, manifest, release []byte, trust generation.Trust, key ed25519.PrivateKey) (NativeDisposalReceipt, error) {
	return disposeBtrfsSnapshot(ctx, p, manifest, release, trust, key, nil)
}

func disposeBtrfsSnapshot(ctx context.Context, p BtrfsProducerProfile, manifest, release []byte, trust generation.Trust, key ed25519.PrivateKey, fault func(string) error) (NativeDisposalReceipt, error) {
	var result NativeDisposalReceipt
	if p.Format != BtrfsProducerFormat || p.Staging.Origin != p.Trust.Origin || p.Staging.Observed.ReadOnly ||
		p.StateVolume.Scope != p.Trust.Profile || len(key) != ed25519.PrivateKeySize ||
		!bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) || !bytes.Equal(key.Public().(ed25519.PublicKey), p.Trust.Producer) {
		return result, ErrInvalid
	}
	ticket, err := VerifyNativeRelease(release, manifest, p.Trust, trust, time.Now())
	if err != nil {
		return result, err
	}
	m, err := VerifyPreparedExport(manifest, p.Trust, time.Now())
	if err != nil {
		return result, err
	}
	staging, err := localfs.OpenRoot(p.Staging.Path)
	if err != nil {
		return result, err
	}
	defer staging.Close()
	stateRoot, err := p.StateVolume.Open(ctx, p.StateDirectory, false)
	if err != nil {
		return result, err
	}
	defer stateRoot.Close()
	if err = localfs.Disjoint(ctx, staging, stateRoot); err != nil {
		return result, err
	}
	guard := func() error {
		if err := checkNativeTree(ctx, staging, p.Staging); err != nil {
			return err
		}
		info, err := staging.Stat(".")
		if err != nil || info.Mode().Perm()&0077 != 0 {
			return ErrInvalid
		}
		return p.StateVolume.CheckHandle(ctx, p.StateDirectory, stateRoot)
	}
	if err = guard(); err != nil {
		return result, err
	}
	dir, err := staging.Open(".")
	if err != nil {
		return result, err
	}
	defer dir.Close()
	store, err := statefile.OpenAt(stateRoot, "disposals", MaxNativeRelease, true)
	if err != nil {
		return result, err
	}
	defer store.Close()
	profile, err := json.Marshal(p)
	if err != nil {
		return result, err
	}
	name := ticket.Operation + ".json"
	expected := NativeDisposalReceipt{Format: NativeDisposalFormat, Binding: storage.Hash(profile), TicketSHA256: storage.Hash(release),
		Operation: ticket.Operation, Snapshot: ticket.Snapshot}
	err = store.WithLock(ctx, func() error {
		if err := guard(); err != nil {
			return err
		}
		save := func(r NativeDisposalReceipt) error {
			if err := guard(); err != nil {
				return err
			}
			r.Signature = nil
			body, err := json.Marshal(r)
			if err != nil {
				return err
			}
			r.Signature = ed25519.Sign(key, append([]byte(NativeDisposalFormat+"\x00"), body...))
			body, err = json.Marshal(r)
			if err != nil {
				return err
			}
			if _, err = verifyNativeDisposal(body, expected, p.Trust.Producer, ticket.IssuedUnix, time.Now().Unix()); err != nil {
				return err
			}
			if err = store.Write(name, body); err != nil {
				return err
			}
			result = r
			return nil
		}
		record := expected
		raw, err := store.Read(name)
		if err == nil {
			record, err = verifyNativeDisposal(raw, expected, p.Trust.Producer, ticket.IssuedUnix, time.Now().Unix())
			if err != nil {
				return err
			}
			if record.PathAbsentUnix != 0 {
				result = record
				return nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		var removedUnix int64
		snapshot, err := localfs.OpenAt(staging, m.Root, false)
		if err == nil {
			defer snapshot.Close()
			proof, err := inspectBtrfsSnapshot(snapshot)
			if err != nil || proof.id != m.SnapshotID || proof.parent != p.Trust.SnapshotOrigin || proof.created != m.SnapshotUnix ||
				(record.Subvolume != 0 && record.Subvolume != proof.subvolume) {
				return ErrInvalid
			}
			if record.Subvolume == 0 {
				disposals, err := localfs.OpenAt(stateRoot, "disposals", false)
				if err != nil {
					return err
				}
				entries, err := readNativeDirectory(disposals, 65)
				disposals.Close()
				if err != nil || len(entries) > 64 {
					return errors.Join(statefile.ErrCapacity, err)
				}
				record.Subvolume, record.IntentUnix = proof.subvolume, time.Now().Unix()
				if err = save(record); err != nil {
					return err
				}
			}
			if err = guard(); err != nil {
				return err
			}
			if err = deleteNativeSnapshot(dir, proof.subvolume); err != nil {
				return err
			}
			removedUnix = time.Now().Unix()
			if fault != nil {
				if err = fault("native-snapshot-kernel-removed"); err != nil {
					return err
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) || record.Subvolume == 0 {
			return errors.Join(ErrInvalid, err)
		}
		if _, err = staging.Lstat(m.Root); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrInvalid, err)
		}
		if err = dir.Sync(); err != nil {
			return err
		}
		// Only a positive kernel reply proves which process removed the name.
		record.RemovedUnix, record.PathAbsentUnix = removedUnix, time.Now().Unix()
		return save(record)
	})
	if err != nil {
		return NativeDisposalReceipt{}, err
	}
	return result, nil
}
