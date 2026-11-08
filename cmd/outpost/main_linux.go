// outpost exposes the versioned worker and offline recovery commands.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/isolation"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/managementservice"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/recovery"
	"github.com/nd4y/outpost/internal/recoverybundle"
	"github.com/nd4y/outpost/internal/sourceagent"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/telemetry"
	"github.com/nd4y/outpost/internal/upload"
	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

var revision = "development"
var errUsage = errors.New("invalid command arguments")

func writeNew(path string, b []byte) error {
	if !filepath.IsAbs(path) {
		return errUsage
	}
	root, e := localfs.OpenRoot(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer root.Close()
	f, e := localfs.OpenFile(root, filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	dir, e := root.Open(".")
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func run(ctx context.Context, args []string) (any, error) {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		return map[string]any{"format": "outpost-cli-1", "commands": []string{"version", "runtime-observe", "runtime-check", "source-probe --store SOURCE --node ORIGIN_ID --output NEW_TREE_BINDING", "source-authority-sign --key OWNER_KEY --input AUTHORITY --output NEW_SIGNED_AUTHORITY", "observation-grant-sign --key OWNER_KEY --input GRANT --output NEW_SIGNED_GRANT", "upload-delegation-sign --key PLANNER_KEY --input DELEGATION --output NEW_SIGNED_DELEGATION", "source-init --bootstrap FILE", "source-next --bootstrap FILE", "source-renew --bootstrap FILE --input NEW_SIGNED_AUTHORITY [--trust NEW_OBSERVATION_GRANT]", "source-settlement-preview --bootstrap FILE --output NEW_REQUEST", "source-settlement-sign --key OWNER_KEY --input REQUEST --output NEW_ADMISSION", "source-settle --bootstrap FILE --input SIGNED_ADMISSION", "source-prepare --bootstrap FILE --input SIGNED_INTENT", "source-run --bootstrap FILE", "source-schedule-set --bootstrap FILE --input SCHEDULE", "source-schedule-status --bootstrap FILE", "source-loop --bootstrap FILE", "source-status --bootstrap FILE", "source-checkpoint --bootstrap FILE --output NEW_CHECKPOINT", "source-recovery-export --bootstrap FILE --input PRIVATE_EXPORT_PROFILE --output NEW_PRIVATE_PACKAGE", "recovery-package-inspect --input PRIVATE_PACKAGE --sha256 EXPECTED_PACKAGE_SHA256", "recovery-package-extract --input PRIVATE_PACKAGE --sha256 EXPECTED_PACKAGE_SHA256 --output NEW_PRIVATE_DIRECTORY", "volume-probe --store DIRECTORY --output PRIVATE_PROBE_FILE", "volume-enroll --store DIRECTORY --input PRIVATE_PROBE_FILE --node NODE_ID --epoch 1 --output NEW_BINDING_FILE", "management-init --input PRIVATE_PROFILE", "management-run --input PRIVATE_PROFILE", "management-status --input PRIVATE_PROFILE", "management-profile-set --input PRIVATE_PROFILE", "management-reconcile --input PRIVATE_PROFILE", "management-snapshot --input PRIVATE_PROFILE --output NEW_PRIVATE_FILE [--max-bytes BYTES]", "management-snapshot-inspect --input PRIVATE_SNAPSHOT --trust EXPECTED_CHECKPOINT [--max-bytes BYTES]", "management-enrollment-sign --key OWNER_KEY --input ENROLLMENT --output NEW_SIGNED_ENROLLMENT", "worker-telemetry-init --bootstrap FILE --input TELEMETRY_PROFILE", "worker-telemetry-status --bootstrap FILE --input TELEMETRY_PROFILE", "worker-telemetry-once --bootstrap FILE --input TELEMETRY_PROFILE", "worker-telemetry-loop --bootstrap FILE --input TELEMETRY_PROFILE", "worker-telemetry-renew --bootstrap FILE --input TELEMETRY_PROFILE", "worker-telemetry-discard --bootstrap FILE --input TELEMETRY_PROFILE --operation EXPECTED_REQUEST_DIGEST", "worker-report-init --bootstrap FILE --input REPORT_PROFILE", "worker-report-set --bootstrap FILE --input REPORT_PROFILE", "worker-report-renew --bootstrap FILE --input REPORT_PROFILE", "worker-report-status --bootstrap FILE --input REPORT_PROFILE", "worker-report-loop --bootstrap FILE --input REPORT_PROFILE", "command-authority-sign --key OWNER_KEY --input AUTHORITY --output NEW_SIGNED_AUTHORITY", "worker-controls-migrate --bootstrap FILE", "worker-controls-rollback --bootstrap FILE", "worker-command-apply --bootstrap FILE --input SIGNED_ENVELOPE", "worker-command-once --bootstrap FILE --input COMMAND_PROFILE", "worker-command-loop --bootstrap FILE --input COMMAND_PROFILE", "recovery-init --input PRIVATE_PROFILE", "trusted-worker-run --bootstrap FILE --input PRIVATE_PROFILE", "worker-init --bootstrap FILE", "worker-run --bootstrap FILE", "worker-status --bootstrap FILE", "worker-discovery-status --bootstrap FILE", "worker-observation-status --bootstrap FILE", "worker-retry --bootstrap FILE --operation ID", "replica-migrate --bootstrap FILE --domain ID", "replica-rollback --bootstrap FILE --domain ID", "config-apply --bootstrap FILE --input FILE", "config-sign --key FILE --input FILE --output FILE", "restore-kit --key FILE --store DIRECTORY --version ID --output DIRECTORY", "verify-kit --key FILE --store DIRECTORY --version ID", "verify-replica --key FILE --trust FILE --store DIRECTORY --generation ID --output NEW_REPORT [--input VERSION_SELECTION]", "restore-replica --key FILE --trust FILE --store DIRECTORY --generation ID --output DIRECTORY [--input SELECTION_FILE]"}}, nil
	}
	if args[0] == "runtime-observe" || args[0] == "runtime-check" {
		if len(args) != 1 {
			return nil, errUsage
		}
		observed := isolation.Observe()
		if args[0] == "runtime-check" {
			if e := observed.Check(); e != nil {
				return nil, e
			}
		}
		return observed, nil
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return nil, errUsage
		}
		return map[string]any{"revision": revision, "cli": "outpost-cli-1", "worker": worker.Format, "workerRead": []string{worker.LegacyFormat, worker.Format, worker.ScheduledFormat, worker.RecoveryFormat}, "managementService": managementservice.Format, "managementSnapshot": management.SnapshotFormat, "ownerRecoveryPackage": recoverybundle.Format, "processIsolation": isolation.Format, "recovery": recovery.ProfileFormat, "bootstrap": worker.BootstrapFormat, "config": control.Format, "configRead": []string{control.Format, control.SettlementConfigFormat}, "sourceSettlement": ingress.SettlementFormat, "generation": generation.Format, "fileKit": filekit.Format, "fileKitRead": []string{filekit.Format, filekit.TypedFormat}, "replicaState": generation.StateFormat}, nil
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	requireIsolation := flags.Bool("require-isolation", false, "require observable bounded process isolation before an operation")
	bootstrap := flags.String("bootstrap", "", "private local bootstrap JSON")
	input := flags.String("input", "", "input file")
	sha256 := flags.String("sha256", "", "independently retained artifact SHA-256")
	output := flags.String("output", "", "new output path")
	key := flags.String("key", "", "private key file")
	store := flags.String("store", "", "file kit directory")
	version := flags.String("version", "", "expected opaque version")
	operation := flags.String("operation", "", "operation ID")
	domain := flags.String("domain", "", "opaque domain ID")
	trustFile := flags.String("trust", "", "public generation trust JSON")
	generationID := flags.String("generation", "", "expected generation checkpoint")
	nodeID := flags.String("node", "", "owner-selected node identity")
	maxBytes := flags.Int64("max-bytes", 16<<20, "bounded private snapshot bytes")
	epoch := flags.Uint64("epoch", 0, "explicit admission epoch")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return nil, errUsage
	}
	if *requireIsolation {
		if e := isolation.Observe().Check(); e != nil {
			return nil, e
		}
	}
	switch args[0] {
	case "management-snapshot-inspect":
		raw, e := worker.ReadPrivate(*trustFile, 4096)
		if e != nil {
			return nil, e
		}
		var trust management.SnapshotTrust
		if e = worker.DecodeInput(raw, &trust, 4096); e != nil {
			return nil, e
		}
		return management.InspectSnapshotFile(ctx, *input, trust, *maxBytes)
	case "management-init", "management-run", "management-status", "management-profile-set", "management-reconcile", "management-snapshot":
		profile, e := managementservice.Load(*input)
		if e != nil {
			return nil, e
		}
		service, e := managementservice.Open(ctx, profile, args[0] == "management-init")
		if e != nil {
			return nil, e
		}
		defer service.Close()
		switch args[0] {
		case "management-run":
			return map[string]any{"service": profile.Local.Node, "stopped": true}, service.Run(ctx)
		case "management-profile-set":
			if e := service.ApplyProfile(ctx); e != nil {
				return nil, e
			}
		case "management-snapshot":
			return service.Snapshot(ctx, *output, *maxBytes)
		case "management-reconcile":
			return service.Reconcile(ctx)
		}
		return service.Status(ctx)
	case "recovery-init", "trusted-worker-run":
		raw, e := worker.ReadPrivate(*input, 1<<20)
		if e != nil {
			return nil, e
		}
		var profile recovery.Profile
		if e = worker.DecodeInput(raw, &profile, 1<<20); e != nil {
			return nil, e
		}
		var b worker.Bootstrap
		if args[0] == "trusted-worker-run" {
			b, e = worker.LoadBootstrap(*bootstrap)
			if e != nil {
				return nil, e
			}
			if b.Node != profile.Node {
				return nil, worker.ErrDenied
			}
		}
		x, e := recovery.OpenExecutor(ctx, profile, args[0] == "recovery-init")
		if e != nil {
			return nil, e
		}
		defer x.Close()
		if args[0] == "recovery-init" {
			return map[string]any{"format": recovery.ProfileFormat, "node": profile.Node, "initialized": true}, nil
		}
		w, close, e := b.OpenTrusted(x)
		if e != nil {
			return nil, e
		}
		defer close()
		return map[string]any{"node": b.Node, "stopped": true}, serveWorker(ctx, b, w)
	case "source-probe":
		binding, e := capture.ProbeTree(ctx, *store, *nodeID)
		if e != nil {
			return nil, e
		}
		raw, e := json.Marshal(binding)
		if e != nil {
			return nil, e
		}
		if e = writeNew(*output, raw); e != nil {
			return nil, e
		}
		return map[string]any{"format": capture.TreeFormat, "probed": true}, nil
	case "source-settlement-preview", "source-settle", "source-recovery-export", "source-renew", "source-init", "source-next", "source-prepare", "source-run", "source-status", "source-checkpoint", "source-schedule-set", "source-schedule-status", "source-loop":
		b, e := sourceagent.Load(*bootstrap)
		if e != nil {
			return nil, e
		}
		if args[0] == "source-schedule-set" || args[0] == "source-schedule-status" {
			control, e := sourceagent.OpenScheduleControl(ctx, b)
			if e != nil {
				return nil, e
			}
			defer control.Close()
			if args[0] == "source-schedule-status" {
				return control.Status(ctx)
			}
			raw, e := worker.ReadPrivate(*input, 16384)
			if e != nil {
				return nil, e
			}
			var schedule sourceagent.Schedule
			if worker.DecodeInput(raw, &schedule, 16384) != nil {
				return nil, errUsage
			}
			if e = control.Configure(ctx, schedule); e != nil {
				return nil, e
			}
			return control.Status(ctx)
		}
		a, e := sourceagent.Open(ctx, b, args[0] == "source-init")
		if e != nil {
			return nil, e
		}
		defer a.Close()
		switch args[0] {
		case "source-settlement-preview":
			item, e := a.SettlementPreview(ctx)
			if e != nil {
				return nil, e
			}
			raw, e := json.Marshal(item)
			if e != nil {
				return nil, e
			}
			if e = writeNew(*output, raw); e != nil {
				return nil, e
			}
			return map[string]any{"format": ingress.SettlementFormat, "signed": false}, nil
		case "source-settle":
			raw, e := worker.ReadPrivate(*input, sourceagent.MaxSettlementAdmission)
			if e != nil {
				return nil, e
			}
			var item control.SettlementAdmission
			if worker.DecodeInput(raw, &item, sourceagent.MaxSettlementAdmission) != nil {
				return nil, errUsage
			}
			if e = a.Settle(ctx, item); e != nil {
				return nil, e
			}
		case "source-recovery-export":
			profile, e := sourceagent.LoadRecoveryExport(*input)
			if e != nil {
				return nil, e
			}
			return a.ExportRecovery(ctx, profile, revision, *output)
		case "source-loop":
			if e = a.RunSchedule(ctx); e != nil {
				return nil, e
			}
			return a.ScheduleStatus(ctx)
		case "source-renew":
			raw, e := worker.ReadPrivate(*input, ingress.MaxDocument)
			if e != nil {
				return nil, e
			}
			var observed []byte
			if *trustFile != "" {
				observed, e = worker.ReadPrivate(*trustFile, observation.MaxDocument)
				if e != nil {
					return nil, e
				}
			}
			return a.Renew(ctx, raw, observed)
		case "source-next":
			if e = a.Next(ctx); e != nil {
				return nil, e
			}
		case "source-prepare":
			raw, e := worker.ReadPrivate(*input, ingress.MaxDocument)
			if e != nil {
				return nil, e
			}
			if e = a.Prepare(ctx, raw); e != nil {
				return nil, e
			}
		case "source-run":
			if e = a.Run(ctx); e != nil {
				return nil, e
			}
		case "source-checkpoint":
			raw, e := a.Checkpoint(ctx)
			if e != nil {
				return nil, e
			}
			if e = writeNew(*output, raw); e != nil {
				return nil, e
			}
		}
		return a.Status(ctx)
	case "volume-probe":
		if !filepath.IsAbs(*output) {
			return nil, errUsage
		}
		observation, e := volume.Probe(ctx, *store)
		if e != nil {
			return nil, e
		}
		raw, e := json.Marshal(observation)
		if e != nil {
			return nil, e
		}
		if e = writeNew(*output, raw); e != nil {
			return nil, e
		}
		return map[string]any{"format": volume.Format, "probed": true}, nil
	case "volume-enroll":
		if !filepath.IsAbs(*output) || !storage.ID(*nodeID) || *epoch == 0 {
			return nil, errUsage
		}
		if _, e := os.Lstat(*output); !errors.Is(e, os.ErrNotExist) {
			return nil, errUsage
		}
		raw, e := worker.ReadPrivate(*input, 4096)
		if e != nil {
			return nil, e
		}
		var observation volume.Observation
		if worker.DecodeInput(raw, &observation, 4096) != nil {
			return nil, errUsage
		}
		binding, e := volume.Enroll(ctx, *store, observation, *nodeID, *epoch)
		if e != nil {
			return nil, e
		}
		raw, e = json.Marshal(binding)
		if e != nil {
			return nil, e
		}
		if e = writeNew(*output, raw); e != nil {
			return nil, e
		}
		return map[string]any{"format": volume.Format, "enrolled": true, "scope": binding.Scope, "epoch": binding.Epoch}, nil
	case "recovery-package-inspect", "recovery-package-extract":
		f, e := recoverybundle.Open(*input)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		if args[0] == "recovery-package-extract" {
			return recoverybundle.Extract(ctx, f, *sha256, *output)
		}
		return recoverybundle.Inspect(ctx, f, *sha256)
	case "restore-replica", "verify-replica":
		if args[0] == "verify-replica" && !filepath.IsAbs(*output) {
			return nil, errUsage
		}
		owner, e := filekit.ReadOwner(*key)
		if e != nil {
			return nil, e
		}
		owner.SigningKey = nil
		raw, e := worker.ReadPrivate(*trustFile, 65536)
		if e != nil {
			return nil, e
		}
		var trust generation.Trust
		if worker.DecodeInput(raw, &trust, 65536) != nil {
			return nil, errUsage
		}
		var selection generation.RecoverySelection
		if *input != "" {
			raw, e = worker.ReadPrivate(*input, 1<<20)
			if e != nil {
				return nil, e
			}
			if worker.DecodeInput(raw, &selection, 1<<20) != nil {
				return nil, errUsage
			}
		}
		if args[0] == "verify-replica" {
			if selection.Directory != "" {
				return nil, errUsage
			}
			report, verifyErr := generation.VerifyMaterialized(ctx, *store, *generationID, trust, owner, selection.Versions)
			if report.Format != "" {
				encoded, e := json.Marshal(report)
				if e != nil {
					return nil, e
				}
				if e = writeNew(*output, encoded); e != nil {
					return nil, e
				}
			}
			return report, verifyErr
		}
		return generation.RecoverMaterialized(ctx, *store, *generationID, trust, owner, selection, *output)
	case "source-settlement-sign", "config-sign", "command-authority-sign", "management-enrollment-sign", "source-authority-sign", "observation-grant-sign", "upload-delegation-sign":
		private, e := worker.ReadPrivate(*key, 65536)
		if e != nil {
			return nil, e
		}
		var signer struct {
			PrivateKey ed25519.PrivateKey `json:"privateKey"`
		}
		if worker.DecodeInput(private, &signer, 65536) != nil {
			return nil, errUsage
		}
		limit := control.MaxConfig
		if args[0] == "source-settlement-sign" {
			limit = sourceagent.MaxSettlementAdmission
		}
		if args[0] == "command-authority-sign" {
			limit = command.MaxAuthority
		}
		if args[0] == "management-enrollment-sign" {
			limit = management.MaxEnrollment
		}
		if args[0] == "source-authority-sign" {
			limit = ingress.MaxDocument
		}
		raw, e := worker.ReadPrivate(*input, limit)
		if e != nil {
			return nil, e
		}
		if args[0] == "source-settlement-sign" {
			var item control.SettlementAdmission
			if worker.DecodeInput(raw, &item, sourceagent.MaxSettlementAdmission) != nil {
				return nil, errUsage
			}
			signed, e := sourceagent.SignSettlementAdmission(item, signer.PrivateKey)
			if e != nil {
				return nil, e
			}
			encoded, e := json.Marshal(signed)
			if e != nil {
				return nil, e
			}
			if e = writeNew(*output, encoded); e != nil {
				return nil, e
			}
			return map[string]any{"format": ingress.SettlementFormat, "signed": true}, nil
		}
		if args[0] == "management-enrollment-sign" {
			var grant management.Enrollment
			if worker.DecodeInput(raw, &grant, management.MaxEnrollment) != nil {
				return nil, errUsage
			}
			signed, e := management.SignEnrollment(grant, signer.PrivateKey)
			if e != nil {
				return nil, e
			}
			if e = writeNew(*output, signed); e != nil {
				return nil, e
			}
			return map[string]any{"format": management.EnrollmentFormat, "node": grant.Node, "revision": grant.Revision, "digest": storage.Hash(signed)}, nil
		}
		if args[0] == "command-authority-sign" {
			var grant command.Authority
			if worker.DecodeInput(raw, &grant, command.MaxAuthority) != nil {
				return nil, errUsage
			}
			signed, e := command.SignAuthority(grant, signer.PrivateKey)
			if e != nil {
				return nil, e
			}
			if e = writeNew(*output, signed); e != nil {
				return nil, e
			}
			return map[string]any{"format": command.AuthorityFormat, "node": grant.Node, "digest": storage.Hash(signed)}, nil
		}
		if args[0] == "observation-grant-sign" {
			var grant observation.Grant
			if worker.DecodeInput(raw, &grant, observation.MaxDocument) != nil {
				return nil, errUsage
			}
			signed, e := observation.SignGrant(grant, signer.PrivateKey)
			if e != nil {
				return nil, e
			}
			if e = writeNew(*output, signed); e != nil {
				return nil, e
			}
			return map[string]any{"format": observation.GrantFormat, "signed": true}, nil
		}
		if args[0] == "upload-delegation-sign" {
			var grant upload.Delegation
			if worker.DecodeInput(raw, &grant, upload.MaxDelegation) != nil {
				return nil, errUsage
			}
			signed, e := upload.SignDelegation(grant, signer.PrivateKey)
			if e != nil {
				return nil, e
			}
			if e = writeNew(*output, signed); e != nil {
				return nil, e
			}
			return map[string]any{"format": upload.DelegationFormat, "signed": true}, nil
		}
		if args[0] == "source-authority-sign" {
			var grant ingress.Authority
			if worker.DecodeInput(raw, &grant, ingress.MaxDocument) != nil {
				return nil, errUsage
			}
			signed, e := ingress.SignAuthority(grant, signer.PrivateKey)
			if e != nil {
				return nil, e
			}
			if e = writeNew(*output, signed); e != nil {
				return nil, e
			}
			return map[string]any{"format": ingress.AuthorityFormat, "signed": true}, nil
		}
		var config control.Config
		if worker.DecodeInput(raw, &config, control.MaxConfig) != nil {
			return nil, errUsage
		}
		signed, e := control.Sign(config, signer.PrivateKey)
		if e != nil {
			return nil, e
		}
		e = writeNew(*output, signed)
		return map[string]any{"node": config.Node, "revision": config.Revision, "digest": storage.Hash(signed)}, e
	case "restore-kit", "verify-kit":
		owner, e := filekit.ReadOwner(*key)
		if e != nil {
			return nil, e
		}
		owner.SigningKey = nil
		s, e := filekit.OpenStore(*store, owner, false)
		if e != nil {
			return nil, e
		}
		defer s.Close()
		var d filekit.Descriptor
		if args[0] == "verify-kit" {
			d, e = s.VerifyKit(ctx, *version)
		} else {
			d, e = s.Restore(ctx, *version, *output)
		}
		if e != nil {
			return nil, e
		}
		return map[string]any{"version": *version, "file": d.File, "bytes": d.Size, "aliases": len(d.Names), "fileKitFormat": d.Format, "kind": d.Kind}, nil
	case "worker-telemetry-init", "worker-telemetry-renew", "worker-telemetry-status", "worker-telemetry-once", "worker-telemetry-loop", "worker-telemetry-discard":
		return runTelemetry(ctx, args[0], *bootstrap, *input, *operation)
	case "worker-report-init", "worker-report-set", "worker-report-renew", "worker-report-status", "worker-report-loop":
		return runReporting(ctx, args[0], *bootstrap, *input)
	case "worker-command-once", "worker-command-loop":
		return runCommands(ctx, args[0], *bootstrap, *input)
	case "worker-init", "worker-run", "worker-status", "worker-discovery-status", "worker-observation-status", "worker-retry", "config-apply", "replica-migrate", "replica-rollback", "worker-controls-migrate", "worker-controls-rollback", "worker-command-apply":
		b, e := worker.LoadBootstrap(*bootstrap)
		if e != nil {
			return nil, e
		}
		w, close, e := b.Open(args[0] == "worker-init")
		if e != nil {
			return nil, e
		}
		defer close()
		switch args[0] {
		case "worker-init":
			return map[string]any{"node": b.Node, "initialized": true}, nil
		case "worker-status":
			return w.Status(ctx)
		case "worker-controls-migrate", "worker-controls-rollback":
			e = w.MigrateControls(ctx, args[0] == "worker-controls-rollback")
			return map[string]any{"node": b.Node, "action": args[0], "completed": e == nil}, e
		case "worker-command-apply":
			raw, e := worker.ReadPrivate(*input, command.MaxEnvelope)
			if e != nil {
				return nil, e
			}
			ack, e := w.ExecuteCommand(ctx, raw)
			if e != nil {
				return nil, e
			}
			if len(ack) == 0 {
				return map[string]any{"state": "QUEUED", "completed": false}, nil
			}
			return json.RawMessage(ack), nil
		case "worker-discovery-status":
			return w.DiscoveryStatus(ctx)
		case "worker-observation-status":
			return w.ObservationStatus(ctx)
		case "worker-retry":
			e = w.Retry(ctx, *operation)
			return map[string]any{"operation": *operation, "retryRequested": e == nil}, e
		case "config-apply":
			raw, e := worker.ReadPrivate(*input, control.MaxConfig)
			if e != nil {
				return nil, e
			}
			e = w.Accept(ctx, raw)
			return map[string]any{"node": b.Node, "configurationAccepted": e == nil}, e
		case "worker-run":
			return map[string]any{"node": b.Node, "stopped": true}, serveWorker(ctx, b, w)
		case "replica-migrate", "replica-rollback":
			e = w.MigrateDomain(ctx, *domain, args[0] == "replica-rollback")
			return map[string]any{"domain": *domain, "action": args[0], "completed": e == nil}, e
		}
	}
	return nil, errUsage
}
func serveWorker(ctx context.Context, b worker.Bootstrap, w *worker.Worker) error {
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	var server *http.Server
	var result chan error
	if b.Listen != "" {
		var e error
		server, e = w.HTTPServer()
		if e != nil {
			return e
		}
		listener, e := net.Listen("tcp", b.Listen)
		if e != nil {
			return e
		}
		result = make(chan error, 1)
		go func() {
			e := server.ServeTLS(listener, "", "")
			if e != nil && !errors.Is(e, http.ErrServerClosed) {
				cancel()
			}
			result <- e
		}()
	}
	e := w.Run(bounded)
	if server != nil {
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		se := server.Shutdown(shutdown)
		done()
		if se != nil {
			_ = server.Close()
		}
		e = errors.Join(e, se)
		if se = <-result; se != nil && !errors.Is(se, http.ErrServerClosed) {
			e = errors.Join(e, se)
		}
	}
	return e
}
func failure(e error) (string, int) {
	switch {
	case errors.Is(e, context.Canceled):
		return "CANCELED", 130
	case errors.Is(e, volume.ErrUnavailable):
		return "VOLUME_UNAVAILABLE", 5
	case errors.Is(e, errUsage):
		return "INVALID_ARGUMENT", 2
	case errors.Is(e, generation.ErrMigrationRequired):
		return "MIGRATION_REQUIRED", 5
	case errors.Is(e, sourceagent.ErrAuthorityChanged):
		return "AUTHORITY_CHANGED", 5
	case errors.Is(e, sourceagent.ErrUnsupported), errors.Is(e, isolation.ErrRequired):
		return "CAPABILITY_UNAVAILABLE", 5
	case errors.Is(e, capture.ErrCopies), errors.Is(e, observation.ErrPending):
		return "COPY_THRESHOLD_PENDING", 5
	case errors.Is(e, telemetry.ErrBlocked):
		return "TELEMETRY_BLOCKED", 5
	case errors.Is(e, recoverybundle.ErrDenied), errors.Is(e, worker.ErrDenied), errors.Is(e, management.ErrDenied), errors.Is(e, control.ErrDenied), errors.Is(e, storage.ErrDenied), errors.Is(e, ingress.ErrDenied), errors.Is(e, observation.ErrDenied), errors.Is(e, upload.ErrDenied):
		return "DENIED", 3
	case errors.Is(e, recoverybundle.ErrInvalid), errors.Is(e, telemetry.ErrInvalid), errors.Is(e, generation.ErrIncomplete), errors.Is(e, management.ErrInvalid), errors.Is(e, filekit.ErrInvalid), errors.Is(e, storage.ErrIntegrity), errors.Is(e, capture.ErrInvalid), errors.Is(e, sourceagent.ErrInvalid):
		return "INCOMPLETE_OR_CORRUPT", 4
	case errors.Is(e, recoverybundle.ErrConflict), errors.Is(e, telemetry.ErrConflict), errors.Is(e, control.ErrRollback), errors.Is(e, management.ErrConflict), errors.Is(e, generation.ErrConflict), errors.Is(e, storage.ErrConflict), errors.Is(e, ingress.ErrConflict), errors.Is(e, os.ErrExist):
		return "CONFLICT", 5
	case errors.Is(e, recoverybundle.ErrCapacity), errors.Is(e, telemetry.ErrCapacity), errors.Is(e, worker.ErrCapacity), errors.Is(e, management.ErrCapacity), errors.Is(e, storage.ErrCapacity), errors.Is(e, statefile.ErrCapacity):
		return "CAPACITY_BLOCKED", 6
	default:
		return "UNAVAILABLE", 7
	}
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	value, e := run(ctx, os.Args[1:])
	if e != nil {
		code, status := failure(e)
		_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"format": "outpost-cli-1", "error": map[string]any{"code": code, "exitCode": status}})
		os.Exit(status)
	}
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"format": "outpost-cli-1", "revision": revision, "result": value}) != nil {
		fmt.Fprintln(os.Stderr, `{"format":"outpost-cli-1","error":{"code":"OUTPUT_FAILED","exitCode":7}}`)
		os.Exit(7)
	}
}
