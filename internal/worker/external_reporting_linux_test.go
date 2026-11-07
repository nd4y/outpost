package worker

import (
	"encoding/json"
	"testing"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

func TestExternalCopyObservationsPreserveReceiptAgeAndUnknown(t *testing.T) {
	id := func(s string) string { return storage.Hash([]byte(s)) }
	node, domain, target, gen := id("worker"), id("domain"), id("target"), id("generation")
	operation := id("operation")
	receipt := upload.Receipt{Target: target, Generation: gen, Operation: operation, Executor: node, Verification: "cached-target-readback", ObservedUnix: 100}
	raw, e := json.Marshal(receipt)
	must(t, e)
	job := JobState{Job: control.Job{Operation: operation, Executor: node, Kind: "upload", Domain: domain, Generation: gen, Target: target}, Phase: "COMPLETE", UpdatedUnix: 500, Receipt: raw}
	check := func(j JobState, state, code string) {
		t.Helper()
		out, e := externalCopyObservations(Status{Jobs: map[string]JobState{operation: j}}, domain, node)
		must(t, e)
		if len(out) != 1 || out[0].State != state || out[0].ErrorCode != code {
			t.Fatal(out)
		}
		if state == "OBSERVED_COMPLETE" {
			if out[0].VerifiedUnix != 100 || out[0].ReceiptDigest != storage.Hash(raw) {
				t.Fatal("age lost", out)
			}
		} else if out[0].VerifiedUnix != 0 || out[0].ReceiptDigest != "" {
			t.Fatal("invented verification", out)
		}
	}
	check(job, "OBSERVED_COMPLETE", "")
	job.UpdatedUnix = 900
	check(job, "OBSERVED_COMPLETE", "")
	job.Phase = "WITHDRAWN"
	check(job, "OBSERVED_COMPLETE", "") // stopping work does not erase historical evidence
	job.Receipt = nil
	job.Phase = "RUNNING"
	check(job, "UNCONFIRMED", "")
	job.Phase = "COMPLETE"
	check(job, "UNAVAILABLE", "MISSING_RECEIPT")
	for _, mutate := range []func(*upload.Receipt){func(r *upload.Receipt) { r.Target = id("different") }, func(r *upload.Receipt) { r.Generation = id("different") }, func(r *upload.Receipt) { r.Operation = id("different") }, func(r *upload.Receipt) { r.Executor = id("different") }, func(r *upload.Receipt) { r.Verification = "HEAD" }, func(r *upload.Receipt) { r.ObservedUnix = 901 }} {
		bad := receipt
		mutate(&bad)
		job.Receipt, e = json.Marshal(bad)
		must(t, e)
		check(job, "UNAVAILABLE", "INVALID_RECEIPT")
	}
	job.Receipt = []byte("broken")
	check(job, "UNAVAILABLE", "INVALID_RECEIPT")
	out, e := externalCopyObservations(Status{Jobs: map[string]JobState{operation: job}}, id("other-domain"), node)
	must(t, e)
	if len(out) != 0 {
		t.Fatal("cross-domain observation")
	}
	job.Job.Target = ""
	if _, e = externalCopyObservations(Status{Jobs: map[string]JobState{operation: job}}, domain, node); e == nil {
		t.Fatal("target guessed")
	}
}
