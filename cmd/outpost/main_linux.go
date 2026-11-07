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

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

var revision = "development"
var errUsage = errors.New("invalid command arguments")

func writeNew(path string, b []byte) error {
	if !filepath.IsAbs(path) {
		return errUsage
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
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
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func run(ctx context.Context, args []string) (any, error) {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		return map[string]any{"format": "outpost-cli-1", "commands": []string{"version", "worker-init --bootstrap FILE", "worker-run --bootstrap FILE", "worker-status --bootstrap FILE", "worker-retry --bootstrap FILE --operation ID", "replica-migrate --bootstrap FILE --domain ID", "replica-rollback --bootstrap FILE --domain ID", "config-apply --bootstrap FILE --input FILE", "config-sign --key FILE --input FILE --output FILE", "restore-kit --key FILE --store DIRECTORY --version ID --output DIRECTORY", "verify-kit --key FILE --store DIRECTORY --version ID", "restore-replica --key FILE --trust FILE --store DIRECTORY --generation ID --output DIRECTORY [--input SELECTION_FILE]"}}, nil
	}
	if args[0] == "version" {
		if len(args) != 1 {
			return nil, errUsage
		}
		return map[string]any{"revision": revision, "cli": "outpost-cli-1", "worker": worker.Format, "config": control.Format, "generation": generation.Format, "fileKit": filekit.Format, "fileKitRead": []string{filekit.Format, filekit.TypedFormat}, "replicaState": generation.StateFormat}, nil
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bootstrap := flags.String("bootstrap", "", "private local bootstrap JSON")
	input := flags.String("input", "", "input file")
	output := flags.String("output", "", "new output path")
	key := flags.String("key", "", "private key file")
	store := flags.String("store", "", "file kit directory")
	version := flags.String("version", "", "expected opaque version")
	operation := flags.String("operation", "", "operation ID")
	domain := flags.String("domain", "", "opaque domain ID")
	trustFile := flags.String("trust", "", "public generation trust JSON")
	generationID := flags.String("generation", "", "expected generation checkpoint")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return nil, errUsage
	}
	switch args[0] {
	case "restore-replica":
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
		return generation.RecoverMaterialized(ctx, *store, *generationID, trust, owner, selection, *output)
	case "config-sign":
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
		raw, e := worker.ReadPrivate(*input, control.MaxConfig)
		if e != nil {
			return nil, e
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
	case "worker-init", "worker-run", "worker-status", "worker-retry", "config-apply", "replica-migrate", "replica-rollback":
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
	case errors.Is(e, errUsage):
		return "INVALID_ARGUMENT", 2
	case errors.Is(e, generation.ErrMigrationRequired):
		return "MIGRATION_REQUIRED", 5
	case errors.Is(e, worker.ErrDenied), errors.Is(e, control.ErrDenied), errors.Is(e, storage.ErrDenied):
		return "DENIED", 3
	case errors.Is(e, generation.ErrIncomplete), errors.Is(e, filekit.ErrInvalid), errors.Is(e, storage.ErrIntegrity):
		return "INCOMPLETE_OR_CORRUPT", 4
	case errors.Is(e, control.ErrRollback), errors.Is(e, generation.ErrConflict), errors.Is(e, storage.ErrConflict), errors.Is(e, os.ErrExist):
		return "CONFLICT", 5
	case errors.Is(e, worker.ErrCapacity), errors.Is(e, storage.ErrCapacity), errors.Is(e, statefile.ErrCapacity):
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
