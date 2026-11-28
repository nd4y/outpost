package filekit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nd4y/outpost/internal/statefile"
)

func TestRepackPeakAdmissionPreservesRetainedVersionsAndKit(t *testing.T) {
	// An allocation equal to the free blocks still has to leave the reserve.
	estimate := allocationPeak{unit: 4096}
	if err := estimate.add(4097); err != nil {
		t.Fatal(err)
	}
	if err := estimate.admit(allocationSpace{unit: 4096, available: 4}, 4097); !errors.Is(err, statefile.ErrCapacity) {
		t.Fatal("new allocation or rounded reserve was not charged", err)
	}
	if err := estimate.admit(allocationSpace{unit: 4096, available: 5}, 4097); err != nil {
		t.Fatal("exact space for charge and reserve refused", err)
	}

	base, s, source, old := fixture(t, 8<<20)
	ctx := t.Context()
	v1 := mustBackup(t, s, source, BackupOptions{Names: []string{"file"}})
	changed := append([]byte(nil), old...)
	changed[2<<20] ^= 1
	if err := os.WriteFile(source, changed, 0600); err != nil {
		t.Fatal(err)
	}
	v2 := mustBackup(t, s, source, BackupOptions{Names: []string{"file"}, File: v1.File, Previous: v1.Version})
	saved := filepath.Join(base, "independent")
	if err := s.Export(ctx, v1.Version, saved); err != nil {
		t.Fatal(err)
	}
	inventory, err := s.objectInventory()
	if err != nil {
		t.Fatal(err)
	}
	savedRoots := make(map[string][]byte, 2)
	for _, version := range []string{v1.Version, v2.Version} {
		raw, err := s.readFile("versions/"+version+".json", MaxRoot)
		if err != nil {
			t.Fatal(err)
		}
		savedRoots[version] = raw
	}
	s.Admit = func(string, int) (func(bool) error, error) {
		t.Fatal("write attempted before peak admission")
		return nil, ErrInvalid
	}
	if _, err := s.RepackWithOptions(ctx, RepackOptions{MinFreeBytes: ^uint64(0)}); !errors.Is(err, statefile.ErrCapacity) {
		t.Fatal("repack did not refuse insufficient overlapping space", err)
	}
	s.Admit = nil
	after, err := s.objectInventory()
	if err != nil || !reflect.DeepEqual(after, inventory) {
		t.Fatal("retained object inventory changed on refusal", err)
	}
	for version, want := range savedRoots {
		raw, err := s.readFile("versions/"+version+".json", MaxRoot)
		if err != nil || !bytes.Equal(raw, want) {
			t.Fatal("retained version root changed on refusal", err)
		}
	}
	for id, size := range inventory {
		raw, err := s.readFile(objectPath(id), MaxObject)
		if err != nil || int64(len(raw)) != size || digest(raw) != id {
			t.Fatal("retained object changed on refusal", err)
		}
	}
	kit, err := OpenStore(saved, s.Owner, false)
	if err != nil {
		t.Fatal(err)
	}
	defer kit.Close()
	mustRestore(t, kit, v1.Version, filepath.Join(base, "independent-before-retry"), old, true)

	if _, err := s.Repack(ctx); err != nil {
		t.Fatal("repack with sufficient capacity did not resume", err)
	}
	mustRestore(t, s, v1.Version, filepath.Join(base, "after-retry-old"), old, false)
	mustRestore(t, s, v2.Version, filepath.Join(base, "after-retry-new"), changed, false)
	mustRestore(t, kit, v1.Version, filepath.Join(base, "independent-after-retry"), old, true)
}
