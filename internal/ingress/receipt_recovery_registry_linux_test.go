package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func interruptedPublication(t *testing.T, expire, published bool) (*registryFixture, ReceiptRecoveryAdmission, string) {
	t.Helper()
	var f *registryFixture
	if expire {
		f = shortSettlementRegistry(t)
	} else {
		f = registryNetwork(t)
	}
	ctx := context.Background()
	must(t, f.client.Begin(ctx))
	point := "capture-replica-complete"
	if !published {
		point = "capture-catalog-durable"
	}
	f.registry.session.Fault = func(p string) error {
		if p == point {
			return errors.New("interrupt before ingress receipt")
		}
		return nil
	}
	stats, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"data"}})
	must(t, e)
	raw, roots := f.catalog(t, []string{stats.Version})
	for id, b := range roots {
		_, e = f.client.Write(ctx, filekit.Object{ID: id, Bytes: len(b)}, b)
		must(t, e)
	}
	if _, _, e = f.client.FinishStep(ctx, raw); e == nil {
		t.Fatal("publication interruption not reached")
	}
	if f.registry.session.state.Complete || f.registry.session.state.Receipt != nil {
		t.Fatal("fixture already has receipt")
	}
	must(t, f.registry.Close())
	f.registry = nil
	f.options.Initialize = false
	if expire {
		time.Sleep(time.Until(time.Unix(f.authority.ExpiresUnix, 0)) + 20*time.Millisecond)
	}
	ordinary := grantFor(t, f, storage.Hash(raw))
	var template Settlement
	must(t, json.Unmarshal(ordinary, &template))
	g := ReceiptRecovery(template)
	g.Format = ReceiptRecoveryFormat
	g.Signature = nil
	grant, e := SignReceiptRecovery(g, f.options.Authority, f.fixture.options.Intent, f.control, time.Now())
	must(t, e)
	return f, ReceiptRecoveryAdmission{Authority: f.options.Authority, Intent: f.fixture.options.Intent, Grant: grant}, storage.Hash(raw)
}

func TestReceiptRecoveryPreservesOriginalPublicationAgeAndSettlement(t *testing.T) {
	f, item, id := interruptedPublication(t, true, true)
	ctx := context.Background()
	proof, e := f.options.Replica.PublishedEvidence(ctx, id)
	must(t, e)
	if proof.VerifiedAt >= f.authority.ExpiresUnix {
		t.Fatal("fixture publication was not under original authority")
	}
	// Also cover publication surviving a crash before receipt pin persistence.
	pin := storage.Hash([]byte(SessionFormat + "/" + f.intent.Tenant + "/" + f.intent.Operation + "/receipt"))
	must(t, f.options.Replica.ReleasePin(ctx, pin))
	for _, point := range []string{"receipt-recovery-authorized", "receipt-recovery-pinned", "receipt-recovery-completed"} {
		killRenewedSlot(t, f, nil, point, item)
		status, e := f.options.Replica.Status(ctx)
		must(t, e)
		_, pinned := status.Pins[pin]
		if pinned != (point != "receipt-recovery-authorized") {
			t.Fatal("incorrect pin boundary", point, pinned)
		}
	}
	receipt, e := RecoverReceipt(ctx, f.options, item, nil, nil)
	must(t, e)
	if receipt.Generation != id || receipt.VerifiedAt != proof.VerifiedAt {
		t.Fatal("recovery refreshed or changed publication", receipt, proof)
	}
	replay, e := RecoverReceipt(ctx, f.options, item, nil, nil)
	must(t, e)
	if replay != receipt {
		t.Fatal("recovery replay changed receipt")
	}
	var selected ReceiptRecovery
	must(t, json.Unmarshal(item.Grant, &selected))
	auditPath := filepath.Join(f.options.Directory, "state/receipt-recovery-"+selected.Intent+".json")
	audit, e := os.ReadFile(auditPath)
	must(t, e)
	if !bytes.Contains(audit, []byte(receiptRecoveryRecordFormat)) || !bytes.Contains(audit, []byte(proof.Verification)) {
		t.Fatal("recovery audit absent")
	}
	settlement := grantFor(t, f, id)
	f.options.Settlement, f.options.SettlementIntent = settlement, item.Intent
	f.registry, e = OpenRegistry(ctx, f.options)
	must(t, e)
	client, e := NewSettlementClient(f.server.URL, item.Authority, item.Intent, settlement, f.options.Owner, f.sourceCert, f.ca.roots, httpLimits)
	must(t, e)
	defer client.Close()
	observed, e := client.SettlementReceipt(ctx)
	must(t, e)
	if observed != receipt {
		t.Fatal("ordinary settlement changed recovered receipt")
	}
	ack, e := client.AcknowledgeStep(ctx, receipt)
	must(t, e)
	if !ack.Clean {
		t.Fatal("recovered receipt did not acknowledge")
	}
	out := filepath.Join(f.base, "recovered-publication")
	_, e = generation.RecoverMaterialized(ctx, filepath.Join(f.base, "replica"), id, f.authority.Trust, f.owner, generation.RecoverySelection{}, out)
	must(t, e)
	want, e := os.ReadFile(f.input)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(out, "data"))
	must(t, e)
	if !bytes.Equal(want, got) {
		t.Fatal("receipt reconstruction changed ciphertext recovery")
	}
	must(t, f.registry.Close())
	f.registry = nil
	f.options.Settlement, f.options.SettlementIntent = nil, nil
	var record receiptRecoveryRecord
	must(t, json.Unmarshal(audit, &record))
	record.Before = storage.Hash([]byte("altered historical state anchor"))
	tampered, e := json.Marshal(record)
	must(t, e)
	must(t, os.WriteFile(auditPath, tampered, 0600))
	if _, e = RecoverReceipt(ctx, f.options, item, nil, nil); e == nil {
		t.Fatal("completed recovery ignored altered signed audit")
	}
}

func TestReceiptRecoveryRefusesUnsupportedProofWithoutChangingSession(t *testing.T) {
	for _, kind := range []string{"unpublished", "missing-proof", "changed-object", "wrong-generation", "unknown-stage", "quota", "guard", "corrupt-audit"} {
		t.Run(kind, func(t *testing.T) {
			f, item, id := interruptedPublication(t, false, kind != "unpublished")
			ctx := context.Background()
			var guard func(context.Context) error
			switch kind {
			case "missing-proof":
				must(t, os.Remove(filepath.Join(f.base, "replica/verification", id)))
			case "changed-object":
				raw, e := f.options.Replica.Catalog(ctx, id)
				must(t, e)
				refs, e := generation.Dependencies(raw, f.authority.Trust)
				must(t, e)
				path := filepath.Join(f.base, "replica/objects", refs[0].ID)
				b, e := os.ReadFile(path)
				must(t, e)
				b[0] ^= 1
				must(t, os.WriteFile(path, b, 0600))
			case "wrong-generation":
				var g ReceiptRecovery
				must(t, json.Unmarshal(item.Grant, &g))
				g.Generation = storage.Hash([]byte("wrong generation"))
				g.Signature = nil
				var e error
				item.Grant, e = SignReceiptRecovery(g, item.Authority, item.Intent, f.control, time.Now())
				must(t, e)
			case "unknown-stage":
				must(t, os.WriteFile(filepath.Join(f.options.Directory, "current/objects/.tmp-uncertain"), []byte("retain"), 0600))
			case "quota":
				f.options.Admission = func(string) statefile.Admission {
					return func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
				}
			case "guard":
				guard = func(context.Context) error { return errors.New("volume no longer admitted") }
			case "corrupt-audit":
				_, e := RecoverReceipt(ctx, f.options, item, nil, func(p string) error {
					if p == "receipt-recovery-authorized" {
						return errors.New("stop")
					}
					return nil
				})
				if e == nil {
					t.Fatal("audit interruption absent")
				}
				must(t, os.WriteFile(filepath.Join(f.options.Directory, "state/receipt-recovery-"+storage.Hash(item.Intent)+".json"), []byte("{}"), 0600))
			}
			path := filepath.Join(f.options.Directory, "current/state/session.json")
			before, e := os.ReadFile(path)
			must(t, e)
			if _, e = RecoverReceipt(ctx, f.options, item, guard, nil); e == nil {
				t.Fatal("unsupported proof accepted", kind)
			}
			after, e := os.ReadFile(path)
			must(t, e)
			if !bytes.Equal(before, after) {
				t.Fatal("rejected recovery modified session", kind)
			}
			if kind == "unknown-stage" {
				got, e := os.ReadFile(filepath.Join(f.options.Directory, "current/objects/.tmp-uncertain"))
				must(t, e)
				if string(got) != "retain" {
					t.Fatal("unknown data changed")
				}
			}
		})
	}
}

func TestReceiptRecoveryExpiredExecutionRetainsAuditAndResumesWithFreshPermission(t *testing.T) {
	f, item, id := interruptedPublication(t, false, true)
	ctx := context.Background()
	var claim ReceiptRecovery
	must(t, json.Unmarshal(item.Grant, &claim))
	claim.ExpiresUnix = time.Now().Unix() + 2
	claim.Signature = nil
	var e error
	item.Grant, e = SignReceiptRecovery(claim, item.Authority, item.Intent, f.control, time.Now())
	must(t, e)
	original := bytes.Clone(item.Grant)
	path := filepath.Join(f.options.Directory, "current/state/session.json")
	before, e := os.ReadFile(path)
	must(t, e)
	_, e = RecoverReceipt(ctx, f.options, item, nil, func(p string) error {
		if p == "receipt-recovery-pinned" {
			time.Sleep(time.Until(time.Unix(claim.ExpiresUnix, 0)) + 30*time.Millisecond)
		}
		return nil
	})
	if e == nil {
		t.Fatal("expired execution committed receipt")
	}
	after, e := os.ReadFile(path)
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("expiry changed session")
	}
	claim.ID = storage.Hash([]byte("fresh recovery approval"))
	claim.NotBefore = time.Now().Unix() - 1
	claim.ExpiresUnix = time.Now().Unix() + 300
	claim.Signature = nil
	item.Grant, e = SignReceiptRecovery(claim, item.Authority, item.Intent, f.control, time.Now())
	must(t, e)
	receipt, e := RecoverReceipt(ctx, f.options, item, nil, nil)
	must(t, e)
	if receipt.Generation != id {
		t.Fatal("fresh permission changed generation")
	}
	raw, e := os.ReadFile(filepath.Join(f.options.Directory, "state/receipt-recovery-"+storage.Hash(item.Intent)+".json"))
	must(t, e)
	var record receiptRecoveryRecord
	must(t, json.Unmarshal(raw, &record))
	if !bytes.Equal(record.OriginalGrant, original) || !bytes.Equal(record.ExecutionGrant, item.Grant) || len(record.Signature) != 64 {
		t.Fatal("lost original or current signed recovery admission")
	}
}
