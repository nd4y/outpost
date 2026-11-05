package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type catalogEntry struct {
	Snapshot   string
	Descriptor descriptor
}

// Discovery only considers committed descriptor snapshots. Unreferenced payload
// snapshots are deliberately invisible to recovery.
func (r runner) catalog(repo, versions string) (map[string]catalogEntry, error) {
	want := map[string]bool{"v2": true}
	switch versions {
	case "v1,v2":
		want["v1"] = true
	case "v2":
	default:
		return nil, errors.New("unsupported expected fixture versions")
	}
	b, err := r.run(repo, nil, "--no-lock", "snapshots", "--json", "--tag", descriptorTag)
	if err != nil {
		return nil, err
	}
	var snapshots []struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(b, &snapshots); err != nil {
		return nil, err
	}
	if len(snapshots) != len(want) {
		return nil, errors.New("unexpected descriptor count")
	}
	got := map[string]catalogEntry{}
	for _, snapshot := range snapshots {
		if !snapshotID.MatchString(snapshot.ID) {
			return nil, errors.New("invalid descriptor snapshot ID")
		}
		b, err = r.run(repo, nil, "--no-lock", "dump", snapshot.ID, "/descriptor.json")
		if err != nil {
			return nil, err
		}
		if len(b) > 64<<10 {
			return nil, errors.New("descriptor too large")
		}
		var d descriptor
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&d); err != nil {
			return nil, err
		}
		var extra any
		if err = decoder.Decode(&extra); err != io.EOF {
			return nil, errors.New("trailing descriptor data")
		}
		if err = validDescriptor(d); err != nil {
			return nil, err
		}
		if !want[d.Version] {
			return nil, errors.New("unexpected descriptor version")
		}
		if _, ok := got[d.Version]; ok {
			return nil, errors.New("duplicate descriptor version")
		}
		got[d.Version] = catalogEntry{snapshot.ID, d}
	}
	return got, nil
}

// A payload may be shared by several descriptors. Removing a descriptor never
// by itself grants permission to remove its payload.
func unreferencedPayloads(candidates []string, remaining map[string]catalogEntry) []string {
	pinned := map[string]bool{}
	for _, entry := range remaining {
		pinned[entry.Descriptor.Payload] = true
	}
	result := []string{}
	for _, id := range candidates {
		if !pinned[id] {
			result = append(result, id)
			pinned[id] = true
		}
	}
	sort.Strings(result)
	return result
}

// Copy regular files into a new directory. No hard links: repacking/deletion in
// this disposable copy must not affect the read-only input kit.
func cloneFixture(from, to string) error {
	info, err := os.Lstat(from)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("fixture source must be a real directory")
	}
	rel, err := filepath.Rel(from, to)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("fixture destination must be outside source")
	}
	if _, err := newDirectory(to); err != nil {
		return err
	}
	var copied int64
	return filepath.WalkDir(from, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dest := filepath.Join(to, rel)
		if entry.IsDir() {
			return os.Mkdir(dest, 0700)
		}
		if !entry.Type().IsRegular() {
			return errors.New("fixture copy rejects links and special files")
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(in, (128<<20)-copied+1))
		copied += n
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if copied > 128<<20 {
			return errors.New("fixture copy exceeds 128MiB")
		}
		return nil
	})
}

func packIDs(repo string) (map[string]bool, error) {
	ids := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(repo, "data"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() || !snapshotID.MatchString(d.Name()) {
			return errors.New("unexpected pack entry")
		}
		ids[d.Name()] = true
		return nil
	})
	return ids, err
}

// This serial synthetic experiment owns a newly cloned repository. It is not a
// concurrent GC implementation, durable job journal or production maintenance API.
func maintenance(ctx context.Context, binary, input, key, work string) (any, error) {
	if !filepath.IsAbs(input) || !filepath.IsAbs(key) {
		return nil, errors.New("absolute kit/key paths required")
	}
	root, err := newDirectory(work)
	if err != nil {
		return nil, err
	}
	r := runner{ctx, binary, key}
	if err = r.checkVersion(); err != nil {
		return nil, err
	}
	kit := filepath.Join(root, "kit")
	if err = cloneFixture(input, kit); err != nil {
		return nil, err
	}
	before, err := r.catalog(kit, "v1,v2")
	if err != nil {
		return nil, err
	}
	// A payload is committed but its descriptor is never successfully published.
	orphan := make([]byte, 64<<10)
	if _, err = rand.Read(orphan); err != nil {
		return nil, err
	}
	orphanID, err := r.backup(kit, bytes.NewReader(orphan), "--stdin", "--stdin-filename", "payload")
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if _, err = r.backup(kit, nil, "--stdin-filename", "descriptor.json", "--tag", descriptorTag, "--stdin-from-command", "--", self, "--phase", "failed-producer"); err == nil {
		return nil, errors.New("failed descriptor producer unexpectedly published")
	}
	after, err := r.catalog(kit, "v1,v2")
	if err != nil {
		return nil, err
	}
	if !maps.Equal(before, after) {
		return nil, errors.New("incomplete publication changed discovery")
	}
	if _, err = verify(ctx, binary, kit, key, filepath.Join(root, "after-publication-failure"), "", "v1,v2"); err != nil {
		return nil, err
	}
	packsBefore, err := packIDs(kit)
	if err != nil {
		return nil, err
	}
	if _, err = r.run(kit, nil, "prune", "--repack-uncompressed", "--max-unused", "0"); err != nil {
		return nil, err
	}
	packsAfter, err := packIDs(kit)
	if err != nil {
		return nil, err
	}
	removed, added := 0, 0
	for id := range packsBefore {
		if !packsAfter[id] {
			removed++
		}
	}
	for id := range packsAfter {
		if !packsBefore[id] {
			added++
		}
	}
	if removed == 0 || added == 0 {
		return nil, errors.New("repack did not replace physical packs")
	}
	if _, err = r.run(kit, nil, "check", "--read-data"); err != nil {
		return nil, err
	}
	if _, err = verify(ctx, binary, kit, key, filepath.Join(root, "after-repack"), "", "v1,v2"); err != nil {
		return nil, err
	}
	// Unpublish v1 first. Capture the completed-command boundary before deleting
	// its payload; another process will recover only v2 from this checkpoint.
	if _, err = r.run(kit, nil, "forget", before["v1"].Snapshot); err != nil {
		return nil, err
	}
	remaining, err := r.catalog(kit, "v2")
	if err != nil {
		return nil, err
	}
	if remaining["v2"] != before["v2"] {
		return nil, errors.New("retirement altered retained descriptor")
	}
	if err = cloneFixture(kit, filepath.Join(root, "interrupted-retirement-kit")); err != nil {
		return nil, err
	}
	garbage := unreferencedPayloads([]string{before["v1"].Descriptor.Payload, orphanID}, remaining)
	if len(garbage) != 0 {
		if _, err = r.run(kit, nil, append([]string{"forget"}, garbage...)...); err != nil {
			return nil, err
		}
	}
	if _, err = r.run(kit, nil, "prune", "--max-unused", "0"); err != nil {
		return nil, err
	}
	if _, err = r.run(kit, nil, "check", "--read-data"); err != nil {
		return nil, err
	}
	final, err := r.catalog(kit, "v2")
	if err != nil {
		return nil, err
	}
	if !maps.Equal(remaining, final) {
		return nil, errors.New("GC altered retained descriptor")
	}
	b, err := r.run(kit, nil, "snapshots", "--json")
	if err != nil {
		return nil, err
	}
	var snapshots []struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(b, &snapshots); err != nil {
		return nil, err
	}
	allowed := map[string]bool{final["v2"].Snapshot: true, final["v2"].Descriptor.Payload: true}
	if len(snapshots) != len(allowed) {
		return nil, errors.New("unexpected snapshots after GC")
	}
	for _, snapshot := range snapshots {
		if !allowed[snapshot.ID] {
			return nil, errors.New("unexpected retained snapshot")
		}
		delete(allowed, snapshot.ID)
	}
	if err = writeJSON(filepath.Join(root, "expected-v2.json"), []descriptor{before["v2"].Descriptor}); err != nil {
		return nil, err
	}
	return map[string]any{"phase": "maintenance", "descriptorFailureRejected": true, "orphanInvisible": true, "packsRemoved": removed, "packsAdded": added, "versionsRecoveredAfterRepack": 2, "retiredVersion": "v1", "garbagePayloadSnapshotsRemoved": len(garbage), "G1": "PARTIAL_FIXTURE_ONLY", "next": "independent verify of retirement checkpoint and final kit; only v2 expected"}, nil
}
