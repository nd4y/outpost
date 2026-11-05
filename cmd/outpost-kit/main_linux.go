// outpost-kit is a local G1 experiment, not the production worker.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
)

var revision = "development"

type report struct {
	Operation       string  `json:"operation"`
	Format          string  `json:"format"`
	Revision        string  `json:"revision"`
	ElapsedSeconds  float64 `json:"elapsedSeconds"`
	MaxRSSKiB       int64   `json:"maxRSSKiB"`
	HeapSystemBytes uint64  `json:"heapSystemBytes"`
	Result          any     `json:"result"`
}

func run(ctx context.Context, args []string) (any, error) {
	if len(args) == 0 {
		return nil, errors.New("operation required: keygen, recovery-key, backup, export, restore, restore-store, repack, retire, gc, inspect")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	key := fs.String("owner", "", "private owner JSON file (0600)")
	store := fs.String("store", "", "absolute store or kit directory")
	source := fs.String("source", "", "stable regular source file")
	dest := fs.String("dest", "", "new destination path")
	version := fs.String("version", "", "expected opaque version from a trusted receipt")
	file := fs.String("file", "", "opaque file identity; empty generates a new identity")
	previous := fs.String("previous", "", "authenticated previous version used for chunk reuse")
	name := fs.String("name", "", "relative restored filename")
	aliases := fs.String("aliases", "", "additional relative names separated by commas")
	if err := fs.Parse(args[1:]); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, filekit.ErrInvalid
	}
	if args[0] == "keygen" {
		o, e := filekit.NewOwner()
		if e != nil {
			return nil, e
		}
		if e = filekit.WriteOwner(*key, o); e != nil {
			return nil, e
		}
		return map[string]string{"domain": o.Domain}, nil
	}
	o, err := filekit.ReadOwner(*key)
	if err != nil {
		return nil, err
	}
	if args[0] == "recovery-key" {
		o.SigningKey = nil
		return nil, filekit.WriteOwner(*dest, o)
	}
	if !filepath.IsAbs(*store) {
		return nil, filekit.ErrInvalid
	}
	s, err := filekit.OpenStore(*store, o, args[0] == "backup")
	if err != nil {
		return nil, err
	}
	defer s.Close()
	switch args[0] {
	case "backup":
		names := []string{*name}
		if *aliases != "" {
			names = append(names, strings.Split(*aliases, ",")...)
		}
		return s.Backup(ctx, *source, filekit.BackupOptions{File: *file, Previous: *previous, Names: names})
	case "export":
		err = s.Export(ctx, *version, *dest)
		return s.Stats, err
	case "restore", "restore-store":
		var d filekit.Descriptor
		if args[0] == "restore" {
			d, err = s.Restore(ctx, *version, *dest)
		} else {
			d, err = s.RestoreVersion(ctx, *version, *dest)
		}
		if err != nil {
			return nil, err
		}
		return struct {
			IO      filekit.Stats `json:"io"`
			Size    int64         `json:"size"`
			Aliases int           `json:"aliases"`
		}{s.Stats, d.Size, len(d.Names)}, nil
	case "repack":
		return s.Repack(ctx)
	case "retire":
		return s.Retire(ctx, strings.Split(*version, ","))
	case "gc":
		if err = s.RemoveAbandoned(ctx); err != nil {
			return nil, err
		}
		n, e := s.GC(ctx)
		return map[string]int{"garbageObjectsRemoved": n}, e
	case "inspect":
		e, d, err := s.LoadVersion(*version)
		if err != nil {
			return nil, err
		}
		objects := map[string]bool{}
		var stored int64
		for _, b := range d.Blocks {
			if !objects[b.Object.ID] {
				objects[b.Object.ID] = true
				stored += int64(b.Object.Bytes)
			}
		}
		for _, p := range e.Parts {
			objects[p.ID] = true
			stored += int64(p.Bytes)
		}
		return map[string]any{"version": e.Version, "file": e.File, "size": d.Size, "blocks": len(d.Blocks), "objects": len(objects), "storedBytes": stored, "descriptorParts": len(e.Parts)}, nil
	default:
		return nil, fmt.Errorf("unknown operation %q", args[0])
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	start := time.Now()
	r, err := run(ctx, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	if err = json.NewEncoder(os.Stdout).Encode(report{os.Args[1], filekit.Format, revision, time.Since(start).Seconds(), usage.Maxrss, mem.HeapSys, r}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
