package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
)

const SnapshotFormat = "outpost-management-snapshot-1"
const SnapshotTrustFormat = "outpost-management-snapshot-trust-1"
const maxSnapshotManifest = 8 << 20
const MaxSnapshotBytes int64 = 1 << 30
const snapshotMagic = "OUTPOST-MANAGEMENT-SNAPSHOT-1\n"

type SnapshotFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Digest string `json:"digest,omitempty"`
	Absent bool   `json:"absent,omitempty"`
}
type SnapshotManifest struct {
	Format          string            `json:"format"`
	Owner           ed25519.PublicKey `json:"owner"`
	Signer          ed25519.PublicKey `json:"signer"`
	Revision        uint64            `json:"revision"`
	ObservedUnix    int64             `json:"observedUnix"`
	ProfileRevision uint64            `json:"profileRevision"`
	ProfileDigest   string            `json:"profileDigest"`
	RegistryDigest  string            `json:"registryDigest"`
	Files           []SnapshotFile    `json:"files"`
	Signature       []byte            `json:"signature,omitempty"`
}

// SnapshotTrust must come from a separately retained checkpoint receipt. The
// snapshot cannot establish that it is the latest surviving state by itself.
type SnapshotTrust struct {
	Format     string            `json:"format"`
	Owner      ed25519.PublicKey `json:"owner"`
	Signer     ed25519.PublicKey `json:"signer"`
	Checkpoint string            `json:"checkpoint"`
}
type SnapshotReceipt struct {
	Format          string `json:"format"`
	Checkpoint      string `json:"checkpoint"`
	Revision        uint64 `json:"revision"`
	ObservedUnix    int64  `json:"observedUnix"`
	ProfileRevision uint64 `json:"profileRevision"`
	ProfileDigest   string `json:"profileDigest"`
	Bytes           int64  `json:"bytes"`
	Files           int    `json:"files"`
	State           string `json:"state"`
	CurrentState    string `json:"currentState"`
	ReplayAllowed   bool   `json:"replayAllowed"`
}
type SnapshotInspection struct {
	SnapshotReceipt
	Receipts []Receipt `json:"receipts"`
	Audit    []Audit   `json:"audit"`
}
type snapshotRef struct {
	path, digest, kind, node string
	optional                 bool
}

func snapshotRefs(s registryState) []snapshotRef {
	refs := map[string]snapshotRef{"registry.json": {path: "registry.json", kind: "registry"}}
	add := func(path, digest, kind, node string, optional bool) {
		refs[path] = snapshotRef{path, digest, kind, node, optional}
	}
	if s.LegacyCheckpoint != "" {
		add("registry-v1-"+s.LegacyCheckpoint+".json", s.LegacyCheckpoint, "checkpoint", "", false)
	}
	nodes := map[string]bool{}
	for node := range s.Configurations {
		nodes[node] = true
	}
	for _, op := range s.ConfigOperations {
		nodes[op.Node] = true
		add("blobs/candidate-"+op.Candidate+".json", op.Candidate, "candidate", op.Node, false)
	}
	for node, p := range s.Configurations {
		add("blobs/candidate-"+p.Digest+".json", p.Digest, "candidate", node, false)
	}
	for node := range nodes {
		_, required := s.Configurations[node]
		add("config-"+node+"/cache.json", "", "cache", node, !required)
	}
	for _, op := range s.CommandOperations {
		add("blobs/command-request-"+op.Request+".json", op.Request, "request", op.Node, false)
		if op.Envelope != "" {
			add("blobs/command-envelope-"+op.Envelope+".json", op.Envelope, "envelope", op.Node, false)
		}
	}
	for key, p := range s.Reports {
		add(reportFile(key, p.Slot), "", "report", key, false)
	}
	out := make([]snapshotRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref)
	}
	// Put the registry first without mutating overlapping slice storage.
	sort.Slice(out, func(i, j int) bool {
		if out[i].kind == "registry" {
			return out[j].kind != "registry"
		}
		if out[j].kind == "registry" {
			return false
		}
		return out[i].path < out[j].path
	})
	return out
}
func snapshotRead(root *os.Root, ref snapshotRef) ([]byte, error) {
	f, e := localfs.OpenFile(root, ref.path, os.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > control.MaxConfig+2<<20 {
		return nil, ErrInvalid
	}
	raw, e := io.ReadAll(io.LimitReader(f, info.Size()+1))
	if e != nil {
		return nil, e
	}
	if int64(len(raw)) != info.Size() {
		return nil, ErrInvalid
	}
	return raw, nil
}
func checkSnapshotDependency(s registryState, ref snapshotRef, raw []byte) error {
	if ref.digest != "" && storage.Hash(raw) != ref.digest {
		return ErrInvalid
	}
	switch ref.kind {
	case "registry":
		_, e := validateRegistry(raw, s.Owner, s.Signer)
		return e
	case "checkpoint":
		old, e := validateRegistry(raw, s.Owner, s.Signer)
		if e != nil {
			return e
		}
		if old.Format != registryFormat || old.Revision >= s.Revision {
			return ErrInvalid
		}
	case "candidate":
		_, e := control.Verify(raw, s.Owner, ref.node)
		return e
	case "request":
		var request command.Request
		if canonical(raw, &request, command.MaxRequest) != nil {
			return ErrInvalid
		}
		authority, e := command.VerifyAuthority(request.Authority, s.Owner)
		if e != nil || request.Validate(authority) != nil || authority.Node != ref.node || !bytes.Equal(authority.Service, s.Signer) {
			return ErrInvalid
		}
		op, ok := s.CommandOperations[request.Operation]
		if !ok || op.Request != storage.Hash(raw) || request.Tenant != op.Audit.Tenant || request.Domain != op.Audit.Domain || request.Reason != op.Audit.Reason || commandRequestDigest(Principal{Actor: op.Audit.Actor}, op.Node, request) != op.Receipt.RequestDigest {
			return ErrInvalid
		}
	case "envelope":
		env, _, e := command.VerifyEnvelope(raw, s.Owner)
		if e != nil {
			return e
		}
		op, ok := s.CommandOperations[env.Request.Operation]
		if !ok || op.Envelope != storage.Hash(raw) || env.Node != op.Node || env.Actor != op.Audit.Actor || env.ConfigurationDigest != op.Configuration || env.Sequence != op.Audit.Sequence || env.AdmittedUnix != op.Audit.ObservedUnix || env.Request.Digest() != op.Request {
			return ErrInvalid
		}
	case "cache":
		cfg, digest, e := control.InspectCacheSnapshot(raw, ref.node, s.Owner)
		if e != nil {
			return e
		}
		p, known := s.Configurations[ref.node]
		if digest == "" {
			if known {
				return ErrInvalid
			}
			return nil
		}
		if known && p.Digest == digest && p.Revision == cfg.Revision {
			return nil
		}
		// A durable cache update may precede its original operation receipt. Keep
		// that evidence; do not roll it back to the older registry pointer.
		for id, op := range s.ConfigOperations {
			if op.Node == ref.node && op.Receipt.State == "ADMITTED" && !resolved(s, id) && op.Candidate == digest && (!known && op.Expected == 0 || known && op.Expected == p.Revision) {
				return nil
			}
		}
		return ErrConflict
	case "report":
		p := s.Reports[ref.node]
		var record reportRecord
		if canonical(raw, &record, maxRegistry) != nil || storage.Hash(record.Document) != p.Digest {
			return ErrInvalid
		}
		enrollment, e := VerifyEnrollment(record.Enrollment, s.Owner)
		if e != nil {
			return e
		}
		report, e := VerifyReport(record.Document, enrollment, time.Now())
		if e != nil {
			return e
		}
		if reportKey(report.Node, report.Domain) != ref.node || report.Sequence != p.Sequence || report.ObservedUnix != p.ObservedUnix || report.EnrollmentRevision != p.EnrollmentRevision {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func snapshotReceipt(m SnapshotManifest, checkpoint string, n int64) SnapshotReceipt {
	return SnapshotReceipt{Format: SnapshotFormat, Checkpoint: checkpoint, Revision: m.Revision, ObservedUnix: m.ObservedUnix, ProfileRevision: m.ProfileRevision, ProfileDigest: m.ProfileDigest, Bytes: n, Files: len(m.Files), State: "HISTORICAL", CurrentState: "UNKNOWN", ReplayAllowed: false}
}

// Snapshot exports a consistent private metadata closure under the registry
// lock. Caller supplies the service execution lease and a new private output.
// No keys, live locks, temporary files, or unreferenced report slots are copied.
// An error never produces a usable receipt, even if a prefix was written.
func (r *Registry) Snapshot(ctx context.Context, w io.Writer, profileRevision uint64, profileDigest string, maxBytes int64) (SnapshotReceipt, error) {
	var receipt SnapshotReceipt
	if w == nil || profileRevision == 0 || !safe(profileRevision) || !storage.ID(profileDigest) || maxBytes < 1 || maxBytes > MaxSnapshotBytes {
		return receipt, ErrInvalid
	}
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		m := SnapshotManifest{Format: SnapshotFormat, Owner: s.Owner, Signer: s.Signer, Revision: s.Revision, ObservedUnix: s.ObservedUnix, ProfileRevision: profileRevision, ProfileDigest: profileDigest}
		refs := snapshotRefs(s)
		var total int64
		for _, ref := range refs {
			if e := r.check(ctx); e != nil {
				return e
			}
			raw, e := snapshotRead(r.root, ref)
			if errors.Is(e, os.ErrNotExist) && ref.optional {
				m.Files = append(m.Files, SnapshotFile{Path: ref.path, Absent: true})
				continue
			}
			if e != nil {
				return e
			}
			if e = checkSnapshotDependency(s, ref, raw); e != nil {
				return e
			}
			file := SnapshotFile{Path: ref.path, Size: int64(len(raw)), Digest: storage.Hash(raw)}
			m.Files = append(m.Files, file)
			total += file.Size
			if total > maxBytes {
				return ErrCapacity
			}
			if ref.kind == "registry" {
				m.RegistryDigest = file.Digest
			}
		}
		raw, _ := json.Marshal(m)
		m.Signature = ed25519.Sign(r.signer, append([]byte(SnapshotFormat+"\x00"), raw...))
		raw, _ = json.Marshal(m)
		total += int64(len(snapshotMagic) + 4 + len(raw))
		if len(raw) > maxSnapshotManifest || total > maxBytes {
			return ErrCapacity
		}
		header := append([]byte(snapshotMagic), make([]byte, 4)...)
		binary.BigEndian.PutUint32(header[len(snapshotMagic):], uint32(len(raw)))
		for _, part := range [][]byte{header, raw} {
			if e := writeSnapshot(ctx, w, part); e != nil {
				return e
			}
		}
		for i, ref := range refs {
			if e := r.check(ctx); e != nil {
				return e
			}
			b, e := snapshotRead(r.root, ref)
			if m.Files[i].Absent {
				if !errors.Is(e, os.ErrNotExist) {
					return ErrConflict
				}
				continue
			}
			if e != nil {
				return e
			}
			if int64(len(b)) != m.Files[i].Size || storage.Hash(b) != m.Files[i].Digest {
				return ErrConflict
			}
			if e = writeSnapshot(ctx, w, b); e != nil {
				return e
			}
		}
		if e := r.check(ctx); e != nil {
			return e
		}
		receipt = snapshotReceipt(m, storage.Hash(raw), total)
		return nil
	})
	if e != nil {
		return SnapshotReceipt{}, e
	}
	return receipt, nil
}
func writeSnapshot(ctx context.Context, w io.Writer, raw []byte) error {
	for len(raw) > 0 {
		if e := ctx.Err(); e != nil {
			return e
		}
		n := len(raw)
		if n > 64<<10 {
			n = 64 << 10
		}
		written, e := w.Write(raw[:n])
		if e != nil {
			return e
		}
		if written != n {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}
func readSnapshot(ctx context.Context, r io.Reader, raw []byte) error {
	for len(raw) > 0 {
		if e := ctx.Err(); e != nil {
			return e
		}
		n := len(raw)
		if n > 64<<10 {
			n = 64 << 10
		}
		if _, e := io.ReadFull(r, raw[:n]); e != nil {
			return e
		}
		raw = raw[n:]
	}
	return nil
}

// InspectSnapshot is keyless and does not create a registry or execute intents.
// It requires the exact independently retained manifest hash, not "any snapshot
// signed by this service". A historical view never claims current authority.
func InspectSnapshot(ctx context.Context, reader io.Reader, trust SnapshotTrust, maxBytes int64) (SnapshotInspection, error) {
	return inspectSnapshot(ctx, reader, trust, maxBytes, nil)
}

// A sink receives only verified dependencies. Its output remains private and
// unpublished until the caller has also verified the end of the stream.
func inspectSnapshot(ctx context.Context, reader io.Reader, trust SnapshotTrust, maxBytes int64, sink func(string, []byte) error) (SnapshotInspection, error) {
	var out SnapshotInspection
	if reader == nil || trust.Format != SnapshotTrustFormat || len(trust.Owner) != 32 || len(trust.Signer) != 32 || bytes.Equal(trust.Owner, trust.Signer) || !storage.ID(trust.Checkpoint) || maxBytes < 1 || maxBytes > MaxSnapshotBytes {
		return out, ErrInvalid
	}
	header := make([]byte, len(snapshotMagic)+4)
	if e := readSnapshot(ctx, reader, header); e != nil {
		return out, e
	}
	if string(header[:len(snapshotMagic)]) != snapshotMagic {
		return out, ErrInvalid
	}
	size := binary.BigEndian.Uint32(header[len(snapshotMagic):])
	if size == 0 || size > maxSnapshotManifest || int64(len(header))+int64(size) > maxBytes {
		return out, ErrCapacity
	}
	raw := make([]byte, size)
	if e := readSnapshot(ctx, reader, raw); e != nil {
		return out, e
	}
	if storage.Hash(raw) != trust.Checkpoint {
		return out, ErrConflict
	}
	var m SnapshotManifest
	if canonical(raw, &m, maxSnapshotManifest) != nil || m.Format != SnapshotFormat || !bytes.Equal(m.Owner, trust.Owner) || !bytes.Equal(m.Signer, trust.Signer) || !safe(m.Revision) || !validTime(m.ObservedUnix) || m.ObservedUnix > time.Now().Unix() || m.ProfileRevision == 0 || !safe(m.ProfileRevision) || !storage.ID(m.ProfileDigest) || !storage.ID(m.RegistryDigest) || len(m.Files) == 0 || len(m.Files) > 24576 {
		return out, ErrInvalid
	}
	sig := m.Signature
	m.Signature = nil
	unsigned, _ := json.Marshal(m)
	m.Signature = sig
	if !ed25519.Verify(trust.Signer, append([]byte(SnapshotFormat+"\x00"), unsigned...), sig) {
		return out, ErrInvalid
	}
	total := int64(len(header)) + int64(size)
	for _, f := range m.Files {
		if f.Absent {
			if f.Size != 0 || f.Digest != "" {
				return out, ErrInvalid
			}
		} else if f.Size < 1 || f.Size > control.MaxConfig+2<<20 || !storage.ID(f.Digest) {
			return out, ErrInvalid
		}
		total += f.Size
		if total > maxBytes {
			return out, ErrCapacity
		}
	}
	if m.Files[0].Path != "registry.json" || m.Files[0].Absent || m.Files[0].Digest != m.RegistryDigest {
		return out, ErrInvalid
	}
	var state registryState
	var refs []snapshotRef
	for i, f := range m.Files {
		if i > 0 && (i >= len(refs) || f.Path != refs[i].path || f.Absent && !refs[i].optional) {
			return out, ErrInvalid
		}
		if f.Absent {
			continue
		}
		b := make([]byte, int(f.Size))
		if e := readSnapshot(ctx, reader, b); e != nil {
			return SnapshotInspection{}, e
		}
		if storage.Hash(b) != f.Digest {
			return SnapshotInspection{}, ErrInvalid
		}
		if i == 0 {
			var e error
			state, e = validateRegistry(b, trust.Owner, trust.Signer)
			if e != nil {
				return out, e
			}
			if state.Revision != m.Revision || state.ObservedUnix != m.ObservedUnix {
				return out, ErrInvalid
			}
			refs = snapshotRefs(state)
			if len(refs) != len(m.Files) {
				return out, ErrInvalid
			}
		}
		if e := checkSnapshotDependency(state, refs[i], b); e != nil {
			return SnapshotInspection{}, e
		}
		if sink != nil {
			if e := sink(refs[i].path, b); e != nil {
				return SnapshotInspection{}, e
			}
		}
	}
	// Reject concatenated snapshots and unexpected/trailing payloads.
	var tail [1]byte
	if e := ctx.Err(); e != nil {
		return out, e
	}
	n, e := reader.Read(tail[:])
	if n != 0 || e != io.EOF {
		return out, ErrInvalid
	}
	out.SnapshotReceipt = snapshotReceipt(m, trust.Checkpoint, total)
	for _, op := range state.Operations {
		out.Receipts = append(out.Receipts, resolutionReceipt(state, op.Receipt))
		out.Audit = append(out.Audit, op.Audit)
	}
	for _, op := range state.ConfigOperations {
		out.Receipts = append(out.Receipts, resolutionReceipt(state, op.Receipt))
		out.Audit = append(out.Audit, op.Audit)
	}
	for _, op := range state.CommandOperations {
		out.Receipts = append(out.Receipts, resolutionReceipt(state, op.Receipt))
		out.Audit = append(out.Audit, op.Audit)
	}
	for _, resolution := range state.Resolutions {
		out.Receipts = append(out.Receipts, resolution.Receipt)
		out.Audit = append(out.Audit, resolution.Audit)
	}
	sort.Slice(out.Receipts, func(i, j int) bool { return strings.Compare(out.Receipts[i].Operation, out.Receipts[j].Operation) < 0 })
	sort.Slice(out.Audit, func(i, j int) bool { return out.Audit[i].Sequence < out.Audit[j].Sequence })
	return out, nil
}

// InspectSnapshotFile accepts only a private, bounded regular local file. It
// never follows links or contacts the original service or any storage target.
func InspectSnapshotFile(ctx context.Context, path string, trust SnapshotTrust, maxBytes int64) (SnapshotInspection, error) {
	f, e := openSnapshotFile(path, maxBytes)
	if e != nil {
		return SnapshotInspection{}, e
	}
	defer f.Close()
	return InspectSnapshot(ctx, f, trust, maxBytes)
}

func openSnapshotFile(path string, maxBytes int64) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maxBytes < 1 || maxBytes > MaxSnapshotBytes {
		return nil, ErrInvalid
	}
	root, e := localfs.OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer root.Close()
	f, e := localfs.OpenFile(root, filepath.Base(path), os.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > maxBytes {
		f.Close()
		return nil, ErrInvalid
	}
	return f, nil
}
