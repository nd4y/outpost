package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const corpusBytes int64 = 32 << 20
const descriptorTag = "outpost-lab-descriptor"

var snapshotID = regexp.MustCompile(`^[a-f0-9]{64}$`)

type descriptor struct {
	Version string `json:"version"`
	Path    string `json:"path"`
	Payload string `json:"payloadSnapshot"`
	Bytes   int64  `json:"bytes"`
	SHA256  string `json:"sha256"`
	Mode    uint32 `json:"mode"`
	Mtime   int64  `json:"mtime"`
}

type runner struct {
	ctx         context.Context
	binary, key string
}

func (r runner) command(repo string, args ...string) *exec.Cmd {
	base := []string{"--no-cache", "--repo", repo, "--password-file", r.key}
	return exec.CommandContext(r.ctx, r.binary, append(base, args...)...)
}

// Bound command diagnostics and metadata. Payload streaming uses a file/hash sink.
type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("command output limit exceeded")
	}
	return b.Buffer.Write(p)
}

func (r runner) run(repo string, input io.Reader, args ...string) ([]byte, error) {
	cmd := r.command(repo, args...)
	cmd.Stdin = input
	stdout := &boundedBuffer{limit: 1 << 20}
	stderr := &boundedBuffer{limit: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("restic %s failed: %w", args[0], err)
	}
	return stdout.Bytes(), nil
}

func (r runner) checkVersion() error {
	b, err := exec.CommandContext(r.ctx, r.binary, "version").Output()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(b), "restic 0.19.1 ") {
		return errors.New("experiment requires restic 0.19.1")
	}
	return nil
}

func newDirectory(name string) (string, error) {
	if name == "" || !filepath.IsAbs(name) {
		return "", errors.New("new absolute work/output directory required")
	}
	name = filepath.Clean(name)
	if err := os.Mkdir(name, 0700); err != nil {
		return "", fmt.Errorf("refuse existing or unavailable experiment directory: %w", err)
	}
	return name, nil
}

func summaryID(raw []byte) (string, error) {
	for _, line := range bytes.Split(raw, []byte("\n")) {
		var item struct {
			Type string `json:"message_type"`
			ID   string `json:"snapshot_id"`
		}
		if json.Unmarshal(line, &item) == nil && item.Type == "summary" && snapshotID.MatchString(item.ID) {
			return item.ID, nil
		}
	}
	return "", errors.New("backup did not return a complete snapshot ID")
}

func (r runner) backup(repo string, input io.Reader, args ...string) (string, error) {
	b, err := r.run(repo, input, append([]string{"backup", "--json", "--host", "outpost-lab"}, args...)...)
	if err != nil {
		return "", err
	}
	return summaryID(b)
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}

func diskBytes(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			s, e := d.Info()
			if e != nil {
				return e
			}
			total += s.Size()
		}
		return nil
	})
	return total, err
}

func prepare(ctx context.Context, binary, work string) (any, error) {
	root, err := newDirectory(work)
	if err != nil {
		return nil, err
	}
	recovery := filepath.Join(root, "recovery")
	if err = os.Mkdir(recovery, 0700); err != nil {
		return nil, err
	}
	key := filepath.Join(recovery, "password")
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		return nil, err
	}
	if err = os.WriteFile(key, []byte(hex.EncodeToString(secret)), 0600); err != nil {
		return nil, err
	}
	r := runner{ctx, binary, key}
	if err = r.checkVersion(); err != nil {
		return nil, err
	}
	primary := filepath.Join(root, "primary")
	kit := filepath.Join(root, "kit")
	for _, repo := range []string{primary, kit} {
		if _, err = r.run(repo, nil, "init", "--repository-version", "2"); err != nil {
			return nil, err
		}
	}
	source := filepath.Join(root, "source")
	if err = os.Mkdir(source, 0700); err != nil {
		return nil, err
	}
	payload := filepath.Join(source, "confidential-name.bin")
	f, err := os.OpenFile(payload, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	_, err = io.CopyN(f, rand.Reader, corpusBytes)
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err = os.WriteFile(filepath.Join(source, "unrelated-private-name.txt"), []byte("unrelated payload must not enter the kit"), 0600); err != nil {
		return nil, err
	}
	var descriptors []descriptor
	var primaryIDs []string
	var kitSizes []int64
	for i := 1; i <= 2; i++ {
		if i == 2 {
			f, e := os.OpenFile(payload, os.O_WRONLY, 0)
			if e != nil {
				return nil, e
			}
			patch := make([]byte, 32<<10)
			if _, e = rand.Read(patch); e == nil {
				_, e = f.WriteAt(patch, corpusBytes/2)
			}
			ce := f.Close()
			if e != nil {
				return nil, e
			}
			if ce != nil {
				return nil, ce
			}
		}
		mtime := time.Unix(1700000000+int64(i), 0)
		if err = os.Chtimes(payload, mtime, mtime); err != nil {
			return nil, err
		}
		id, e := r.backup(primary, nil, source)
		if e != nil {
			return nil, e
		}
		primaryIDs = append(primaryIDs, id)
		// Native producer-status checking prevents committing a truncated dump as a valid kit payload.
		args := []string{"--stdin-filename", "payload", "--stdin-from-command", "--", binary, "--no-cache", "--repo", primary, "--password-file", key, "dump", id, filepath.ToSlash(payload)}
		payloadID, e := r.backup(kit, nil, args...)
		if e != nil {
			return nil, e
		}
		hash, e := hashFile(payload)
		if e != nil {
			return nil, e
		}
		d := descriptor{Version: fmt.Sprintf("v%d", i), Path: "fixture/confidential-name.bin", Payload: payloadID, Bytes: corpusBytes, SHA256: hash, Mode: 0600, Mtime: mtime.Unix()}
		data, e := json.Marshal(d)
		if e != nil {
			return nil, e
		}
		if _, e = r.backup(kit, bytes.NewReader(data), "--stdin", "--stdin-filename", "descriptor.json", "--tag", descriptorTag); e != nil {
			return nil, e
		}
		descriptors = append(descriptors, d)
		size, e := diskBytes(kit)
		if e != nil {
			return nil, e
		}
		kitSizes = append(kitSizes, size)
	}
	// A failed producer must not publish an empty snapshot or change the prior complete state.
	before, e := r.run(kit, nil, "snapshots", "--json")
	if e != nil {
		return nil, e
	}
	self, e := os.Executable()
	if e != nil {
		return nil, e
	}
	_, producerErr := r.backup(kit, nil, "--stdin-filename", "payload", "--stdin-from-command", "--", self, "--phase", "failed-producer")
	if producerErr == nil {
		return nil, errors.New("failed producer unexpectedly accepted")
	}
	after, e := r.run(kit, nil, "snapshots", "--json")
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(before, after) {
		return nil, errors.New("failed producer altered published snapshots")
	}
	// Primary history removal and maintenance cannot invalidate a self-contained kit.
	if _, err = r.run(primary, nil, "forget", primaryIDs[0], "--prune"); err != nil {
		return nil, err
	}
	if _, err = r.run(kit, nil, "prune"); err != nil {
		return nil, err
	}
	if _, err = r.run(kit, nil, "check", "--read-data"); err != nil {
		return nil, err
	}
	if err = writeJSON(filepath.Join(recovery, "expected.json"), descriptors); err != nil {
		return nil, err
	}
	result := map[string]any{"phase": "prepare", "fixtureBytes": corpusBytes, "versions": 2, "patchBytes": 32 << 10, "kitBytesAfterV1": kitSizes[0], "kitBytesAddedV2": kitSizes[1] - kitSizes[0], "fullPlaintextReadPerVersion": corpusBytes, "producerFailureRejected": true, "G1": "NOT_ACCEPTED", "next": "verify in a separate container with only kit and recovery inputs"}
	if err = writeJSON(filepath.Join(root, "prepare.json"), result); err != nil {
		return nil, err
	}
	return result, nil
}

func validDescriptor(d descriptor) error {
	if (d.Version != "v1" && d.Version != "v2") || d.Path != "fixture/confidential-name.bin" || !snapshotID.MatchString(d.Payload) || !snapshotID.MatchString(d.SHA256) || d.Bytes != corpusBytes || d.Mode != 0600 || d.Mtime < 1 {
		return errors.New("invalid synthetic descriptor")
	}
	return nil
}

func (r runner) restore(repo, dir string, d descriptor) error {
	if err := validDescriptor(d); err != nil {
		return err
	}
	tmp := filepath.Join(dir, d.Version+".partial")
	final := filepath.Join(dir, d.Version+".bin")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	sink := &payloadSink{writer: io.MultiWriter(f, h), remaining: d.Bytes}
	cmd := r.command(repo, "--no-lock", "dump", d.Payload, "/payload")
	cmd.Stdout = sink
	cmd.Stderr = &boundedBuffer{limit: 64 << 10}
	err = cmd.Run()
	syncErr := f.Sync()
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("payload read failed: %w", err)
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if sink.remaining != 0 || hex.EncodeToString(h.Sum(nil)) != d.SHA256 {
		return errors.New("payload length/hash mismatch; partial file not published")
	}
	mtime := time.Unix(d.Mtime, 0)
	if err = os.Chtimes(tmp, mtime, mtime); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

type payloadSink struct {
	writer    io.Writer
	remaining int64
}

func (s *payloadSink) Write(p []byte) (int, error) {
	if int64(len(p)) > s.remaining {
		return 0, errors.New("payload exceeds descriptor")
	}
	n, e := s.writer.Write(p)
	s.remaining -= int64(n)
	return n, e
}

func verify(ctx context.Context, binary, kit, key, output, oracle string) (any, error) {
	if !filepath.IsAbs(kit) || !filepath.IsAbs(key) {
		return nil, errors.New("absolute kit/key paths required")
	}
	dir, err := newDirectory(output)
	if err != nil {
		return nil, err
	}
	r := runner{ctx, binary, key}
	if err = r.checkVersion(); err != nil {
		return nil, err
	}
	raw, err := r.run(kit, nil, "--no-lock", "snapshots", "--json", "--tag", descriptorTag)
	if err != nil {
		return nil, err
	}
	var snapshots []struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(raw, &snapshots); err != nil {
		return nil, err
	}
	if len(snapshots) != 2 {
		return nil, errors.New("fixture requires exactly two descriptor snapshots")
	}
	got := map[string]descriptor{}
	for _, snap := range snapshots {
		if !snapshotID.MatchString(snap.ID) {
			return nil, errors.New("invalid snapshot ID")
		}
		b, e := r.run(kit, nil, "--no-lock", "dump", snap.ID, "/descriptor.json")
		if e != nil {
			return nil, e
		}
		if len(b) > 64<<10 {
			return nil, errors.New("descriptor too large")
		}
		var d descriptor
		if e = json.Unmarshal(b, &d); e != nil {
			return nil, e
		}
		if e = validDescriptor(d); e != nil {
			return nil, e
		}
		if _, exists := got[d.Version]; exists {
			return nil, errors.New("duplicate version")
		}
		if e = r.restore(kit, dir, d); e != nil {
			return nil, e
		}
		got[d.Version] = d
	}
	// Optional oracle compares fixture truth only after recovery; no lookup depends on it.
	if oracle != "" {
		f, e := os.Open(oracle)
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(f, 64<<10))
		ce := f.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
		var expected []descriptor
		if e = json.Unmarshal(b, &expected); e != nil {
			return nil, e
		}
		if len(expected) != 2 {
			return nil, errors.New("invalid oracle")
		}
		for _, want := range expected {
			if got[want.Version] != want {
				return nil, errors.New("restored descriptor differs from fixture")
			}
			st, e := os.Stat(filepath.Join(dir, want.Version+".bin"))
			if e != nil {
				return nil, e
			}
			if st.Mode().Perm() != 0600 || st.ModTime().Unix() != want.Mtime {
				return nil, errors.New("mode/mtime not restored")
			}
		}
	}
	return map[string]any{"phase": "verify", "versionsRecovered": len(got), "payloadHashLength": "PASS", "fixtureModeMtime": "applied; checked when oracle supplied", "oracleUsed": oracle != "", "G1": "PARTIAL_FIXTURE_ONLY", "unverified": []string{"full-scale cost", "ACL/xattr/hardlinks", "interrupted kit publication", "cross-version GC deletion", "opaque keyless transfer", "production source adapter"}}, nil
}
