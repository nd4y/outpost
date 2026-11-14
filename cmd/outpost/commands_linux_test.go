package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

// Reuse the real CLI volume/key/bootstrap fixture without a second fake stack.
func checkCLICommands(t *testing.T, base, bootstrap, ownerFile string, cfg control.Config, owner ed25519.PrivateKey) {
	t.Helper()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	ctx := context.Background()
	for _, action := range []string{"worker-controls-rollback", "worker-controls-migrate"} {
		_, e := run(ctx, []string{action, "--bootstrap", bootstrap})
		must(e)
	}
	serviceKey := ed25519.NewKeyFromSeed(make([]byte, 32))
	service := serviceKey.Public().(ed25519.PublicKey)
	d := cfg.Domains[0].Trust
	tenant := storage.Hash([]byte("tenant"))
	grant := command.Authority{Format: command.AuthorityFormat, Service: service, Node: cfg.Node, Tenant: tenant, Domain: d.Domain, Repository: d.Repository, WriterEpoch: d.Epoch, AuthorityEpoch: 1, Kinds: []string{"pause", "resume"}, NotBefore: cfg.NotBefore, ExpiresUnix: cfg.ExpiresUnix}
	input := filepath.Join(base, "command-authority-input.json")
	raw, e := json.Marshal(grant)
	must(e)
	must(os.WriteFile(input, raw, 0600))
	output := filepath.Join(base, "command-authority.json")
	args := []string{"command-authority-sign", "--key", ownerFile, "--input", input, "--output", output}
	_, e = run(ctx, args)
	must(e)
	if _, e = run(ctx, args); !errors.Is(e, os.ErrExist) {
		t.Fatal("authority overwritten", e)
	}
	authority, e := os.ReadFile(output)
	must(e)
	cfg.Revision++
	cfg.Commands = []json.RawMessage{authority}
	raw, e = control.Sign(cfg, owner)
	must(e)
	config := filepath.Join(base, "command-config.json")
	must(os.WriteFile(config, raw, 0600))
	_, e = run(ctx, []string{"config-apply", "--bootstrap", bootstrap, "--input", config})
	must(e)
	env := command.Envelope{Format: command.EnvelopeFormat, Actor: storage.Hash([]byte("operator")), Service: command.Identity(service), Node: cfg.Node, Sequence: 1, ConfigurationDigest: storage.Hash(raw), AdmittedUnix: time.Now().Unix(), Request: command.Request{Operation: storage.Hash([]byte("pause-cli")), Reason: "OPERATOR_REQUEST", Tenant: tenant, Domain: d.Domain, Kind: "pause", ExpectedRevision: cfg.Revision, Authority: authority, ExpiresUnix: time.Now().Unix() + 60}}
	envelope, e := command.SignEnvelope(env, owner.Public().(ed25519.PublicKey), serviceKey)
	must(e)
	input = filepath.Join(base, "command-envelope.json")
	must(os.WriteFile(input, envelope, 0600))
	result, e := run(ctx, []string{"worker-command-apply", "--bootstrap", bootstrap, "--input", input})
	must(e)
	var ack command.Ack
	must(json.Unmarshal(result.(json.RawMessage), &ack))
	if ack.State != "COMPLETE" {
		t.Fatal(ack)
	}
	if _, e = run(ctx, []string{"worker-controls-rollback", "--bootstrap", bootstrap}); e == nil {
		t.Fatal("CLI discarded hold")
	}
	profile := worker.CommandProfile{Format: worker.CommandProfileFormat, Endpoint: "https://127.0.0.1:1", Identity: command.Identity(service), EnrollmentFile: filepath.Join(base, "enrollment.json"), PollSeconds: 1, RetrySeconds: 5, AttemptSeconds: 1}
	raw, e = json.Marshal(profile)
	must(e)
	input = filepath.Join(base, "commands-profile.json")
	must(os.WriteFile(input, raw, 0600))
	if _, e = run(ctx, []string{"worker-command-once", "--bootstrap", bootstrap, "--input", input}); !errors.Is(e, management.ErrUnavailable) {
		t.Fatal("unavailable controller hidden", e)
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, e := run(bounded, []string{"worker-command-loop", "--bootstrap", bootstrap, "--input", input})
		done <- e
	}()
	// Observe the durable retry before cancelling. A fixed startup sleep races
	// volume admission and journal fsync on a throttled HDD race-detector run.
	deadline := time.Now().Add(3 * time.Second)
	observed := false
	for time.Now().Before(deadline) {
		value, err := run(ctx, []string{"worker-status", "--bootstrap", bootstrap})
		must(err)
		state := value.(worker.Status)
		if state.Controls.Delivery != nil && state.Controls.Delivery.Phase == "RETRY_WAIT" {
			observed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		must(err)
	case <-time.After(2 * time.Second):
		t.Fatal("command loop did not join")
	}
	if !observed {
		t.Fatal("command loop never persisted retry")
	}
	result, e = run(ctx, []string{"worker-status", "--bootstrap", bootstrap})
	must(e)
	s := result.(worker.Status)
	if s.Controls.Delivery == nil || s.Controls.Delivery.Phase != "RETRY_WAIT" || !s.Controls.Domains[d.Domain] {
		t.Fatal("loop error missing or changed pause")
	}
}
