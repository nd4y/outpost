package sourceagent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nd4y/outpost/internal/storage"
)

type ingressScaleResult struct {
	Generation                                        string `json:"generation"`
	PayloadBytes, MetadataBytes, SourceAllocatedBytes int64
	FilePayloadBytes, DescriptorBytes                 int64
	Seconds                                           float64
	Milestones                                        *Milestones `json:"milestones"`
	Carried                                           bool        `json:"carried,omitempty"`
	PriorPayloadBytes                                 int64       `json:"priorPayloadBytes,omitempty"`
	PriorMetadataBytes                                int64       `json:"priorMetadataBytes,omitempty"`
	PriorObjectTypeSplitUnknown                       bool        `json:"priorObjectTypeSplitUnknown,omitempty"`
	TimingBasis                                       string      `json:"timingBasis,omitempty"`
}

type ingressScalePrior struct {
	Base              ingressScaleResult
	Generated         json.RawMessage
	Payload, Metadata int64
	LogSHA256         string
}

// The exact old failed log binds carried observations. It is not relabelled as
// a successful execution. Only the known base-complete/patched-sealed boundary
// is supported; changed/ambiguous trailing counters fail before opening actors.
func readIngressScalePrior(path, digest string, size int64) (ingressScalePrior, error) {
	var out ingressScalePrior
	if !storage.ID(digest) || size < 1 || size > 100<<30 || !filepath.IsAbs(path) {
		return out, ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return out, ErrInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 16<<20 {
		return out, ErrInvalid
	}
	raw, err := os.ReadFile(path)
	if err != nil || storage.Hash(raw) != digest || !bytes.Contains(raw, []byte("panic: test timed out after 36h0m0s")) ||
		!bytes.Contains(raw, []byte("INGRESS_FULL_TERMINAL=2")) || bytes.Contains(raw, []byte("INGRESS_SCALE_PASS bytes=")) {
		return out, ErrInvalid
	}
	baseCount, generatedCount, stable := 0, 0, 0
	lastPhase := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if _, text, found := strings.Cut(line, "INGRESS_SCALE_CAPTURE phase=base result="); found {
			baseCount++
			if json.Unmarshal([]byte(text), &out.Base) != nil {
				return out, ErrInvalid
			}
		}
		if _, text, found := strings.Cut(line, "INGRESS_SCALE_GENERATED "); found {
			generatedCount++
			if !json.Valid([]byte(text)) {
				return out, ErrInvalid
			}
			out.Generated = append([]byte(nil), text...)
		}
		if _, text, found := strings.Cut(line, "INGRESS_SCALE_PROGRESS "); found {
			var phase string
			var payload, metadata int64
			if n, err := fmt.Sscanf(text, "phase=%s received-object-body-bytes=%d received-other-put-body-bytes=%d", &phase, &payload, &metadata); n != 3 || err != nil {
				return out, ErrInvalid
			}
			if phase == "capture-patched" && phase == lastPhase && payload == out.Payload && metadata == out.Metadata {
				stable++
			} else {
				stable = 0
			}
			lastPhase, out.Payload, out.Metadata = phase, payload, metadata
		}
	}
	var generated struct {
		FileBytes, AllocatedBytes int64
		SHA256                    string
	}
	if json.Unmarshal(out.Generated, &generated) != nil || generated.FileBytes != size || generated.AllocatedBytes < size || !storage.ID(generated.SHA256) ||
		baseCount != 1 || generatedCount != 1 || lastPhase != "capture-patched" || stable < 1 || !storage.ID(out.Base.Generation) || out.Base.Seconds <= 0 ||
		out.Base.PayloadBytes < 1 || out.Base.PayloadBytes > size*108/100 || out.Base.MetadataBytes < 0 || out.Base.SourceAllocatedBytes < 0 || out.Base.SourceAllocatedBytes > 2<<30 ||
		out.Base.FilePayloadBytes < 0 || out.Base.DescriptorBytes < 0 || out.Base.FilePayloadBytes+out.Base.DescriptorBytes != out.Base.PayloadBytes ||
		out.Base.Milestones == nil || out.Base.Milestones.SnapshotUnix < 1 || out.Base.Milestones.ProviderReleaseUnix < out.Base.Milestones.SnapshotUnix || out.Base.Milestones.FirstReplicaVerifiedUnix < out.Base.Milestones.SnapshotUnix ||
		out.Payload <= out.Base.PayloadBytes || out.Payload > size*108/100+(128<<20) || out.Metadata < out.Base.MetadataBytes || out.Metadata > 256<<20 ||
		out.Payload-out.Base.PayloadBytes+out.Metadata-out.Base.MetadataBytes > 128<<20 {
		return out, ErrInvalid
	}
	out.LogSHA256 = digest
	return out, nil
}

func TestIngressScaleResumeLogBindingsRejectAmbiguousCounters(t *testing.T) {
	const size = 1 << 20
	base := ingressScaleResult{Generation: storage.Hash([]byte("base")), PayloadBytes: 100, MetadataBytes: 10,
		SourceAllocatedBytes: 4096, FilePayloadBytes: 80, DescriptorBytes: 20, Seconds: 2,
		Milestones: &Milestones{SnapshotUnix: 1, FirstReplicaVerifiedUnix: 2, ProviderReleaseUnix: 3}}
	encoded, err := json.Marshal(base)
	must(t, err)
	generated := fmt.Sprintf(`{"fileBytes":%d,"allocatedBytes":%d,"sha256":%q}`, size, size, storage.Hash([]byte("oracle")))
	progress := "INGRESS_SCALE_PROGRESS phase=capture-patched received-object-body-bytes=150 received-other-put-body-bytes=20\n"
	valid := "INGRESS_SCALE_GENERATED " + generated + "\nINGRESS_SCALE_CAPTURE phase=base result=" + string(encoded) + "\n" + progress + progress +
		"panic: test timed out after 36h0m0s\nINGRESS_FULL_TERMINAL=2\n"
	for name, text := range map[string]string{
		"valid":              valid,
		"changing-last-body": strings.Replace(valid, progress+progress, progress+strings.Replace(progress, "bytes=150", "bytes=151", 1), 1),
		"wrong-final-phase":  strings.Replace(valid, progress+progress, progress+strings.Replace(progress, "capture-patched", "capture-unchanged", 1), 1),
		"duplicate-base":     strings.Replace(valid, progress+progress, "INGRESS_SCALE_CAPTURE phase=base result="+string(encoded)+"\n"+progress+progress, 1),
		"successful-old-run": valid + "INGRESS_SCALE_PASS bytes=1048576\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "old.log")
			must(t, os.WriteFile(path, []byte(text), 0600))
			prior, err := readIngressScalePrior(path, storage.Hash([]byte(text)), size)
			if name == "valid" {
				must(t, err)
				if prior.Base.Generation != base.Generation || prior.Payload != 150 || prior.Metadata != 20 {
					t.Fatal("carried observations changed")
				}
				if _, err = readIngressScalePrior(path, storage.Hash([]byte("different")), size); err == nil {
					t.Fatal("wrong original log digest admitted")
				}
			} else if err == nil {
				t.Fatal("ambiguous prior observations admitted")
			}
			kept, err := os.ReadFile(path)
			must(t, err)
			if string(kept) != text {
				t.Fatal("input log was modified")
			}
		})
	}
}
