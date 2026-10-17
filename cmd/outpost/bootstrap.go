package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Bootstrap receives the enrollment key on stdin; secrets never enter Docker Env.
func bootstrap(input io.Reader, state, data string) error {
	if os.Geteuid() == 0 {
		return errors.New("bootstrap must run as the Outpost UID")
	}
	entries, err := os.ReadDir(state)
	if err != nil {
		return errors.New("cannot read state directory")
	}
	if len(entries) != 0 {
		return errors.New("bootstrap requires an empty state volume")
	}
	scanner := bufio.NewScanner(io.LimitReader(input, 4097))
	if !scanner.Scan() {
		return errors.New("bootstrap requires a setup key on stdin")
	}
	key := scanner.Text()
	if len(key) < 16 || len(key) > 512 || strings.ContainsAny(key, "\r\n\x00") {
		return errors.New("invalid setup key")
	}
	if scanner.Scan() || scanner.Err() != nil {
		return errors.New("bootstrap accepts exactly one line")
	}
	// Check the selected bind without changing existing host permissions.
	f, err := os.CreateTemp(data, ".outpost-write-check-")
	if err != nil {
		return errors.New("backup directory is not writable by UID 65532")
	}
	name := f.Name()
	if err = f.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err = os.Remove(name); err != nil {
		return err
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return err
	}
	for filename, value := range map[string]string{"rsync-password": hex.EncodeToString(random), "setup-key": key} {
		if err = os.WriteFile(filepath.Join(state, filename), []byte(value+"\n"), 0600); err != nil {
			return errors.New("cannot write bootstrap state")
		}
	}
	return nil
}

func persistentSecret(name string) string {
	switch name {
	case "OUTPOST_RSYNC_PASSWORD":
		return "/state/rsync-password"
	case "NB_SETUP_KEY":
		return "/state/setup-key"
	}
	return ""
}

func credentials() error {
	value, err := secret("OUTPOST_RSYNC_PASSWORD")
	if err != nil || value == "" {
		return errors.New("rsync credentials are unavailable")
	}
	_, err = fmt.Fprintln(os.Stdout, value)
	return err
}
