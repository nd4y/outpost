// Outpost supervises a rootless NetBird peer and a loopback-only rsync receiver.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"

	"regexp"
	"strings"
	"syscall"
	"time"
)

const rsyncPort = "8873"

var userPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	command := "run"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	var err error
	switch command {
	case "run":
		err = run(true)
	case "receiver-local":
		err = run(false) // diagnostic mode: still loopback-only
	case "bootstrap":
		err = bootstrap(os.Stdin, "/state", "/data")
	case "credentials":
		err = credentials()
	case "health":
		err = health()
	default:
		err = errors.New("supported commands: run, health, receiver-local, bootstrap, credentials")
	}
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func secret(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" && os.Getenv(name+"_FILE") == "" {
		if path := persistentSecret(name); path != "" {
			data, err := os.ReadFile(path)
			if err == nil {
				value = strings.TrimSuffix(string(data), "\n")
			} else if !os.IsNotExist(err) {
				return "", errors.New("cannot read persistent secret")
			}
		}
	}
	if file := os.Getenv(name + "_FILE"); file != "" {
		if value != "" {
			return "", fmt.Errorf("set only %s or %s_FILE", name, name)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("cannot read %s_FILE", name)
		}
		value = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("%s contains prohibited characters", name)
	}
	return value, nil
}

func configure() error {
	if os.Geteuid() == 0 {
		return errors.New("Outpost must run as a non-root UID; grant that UID write access to /data and /state")
	}
	if err := os.MkdirAll("/run/outpost", 0700); err != nil {
		return err
	}
	for _, p := range []string{"/data", "/state"} {
		st, err := os.Lstat(p)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must be a real writable directory", p)
		}
		f, err := os.CreateTemp(p, ".outpost-write-check-")
		if err != nil {
			return fmt.Errorf("%s is not writable by UID %d; fix only the dedicated directory permissions", p, os.Geteuid())
		}
		name := f.Name()
		_ = f.Close()
		if err = os.Remove(name); err != nil {
			return err
		}
	}
	username := os.Getenv("OUTPOST_RSYNC_USER")
	if username == "" {
		username = "backup"
	}
	if !userPattern.MatchString(username) {
		return errors.New("invalid OUTPOST_RSYNC_USER")
	}
	password, err := secret("OUTPOST_RSYNC_PASSWORD")
	if err != nil {
		return err
	}
	if len(password) < 24 || len(password) > 256 || strings.Contains(password, ":") {
		return errors.New("OUTPOST_RSYNC_PASSWORD must contain 24-256 bytes, no colon or newline")
	}
	if err = os.WriteFile("/run/outpost/rsync.secrets", []byte(username+":"+password+"\n"), 0600); err != nil {
		return err
	}
	// No exec hooks, remote shell, chroot privilege or listener on the Docker IP.
	config := fmt.Sprintf(`pid file = /run/outpost/rsync.pid
lock file = /run/outpost/rsync.lock
log file = /dev/stdout
port = 8873
address = 127.0.0.1
use chroot = no
reverse lookup = no
max connections = 4
timeout = 900
strict modes = yes
[backup]
path = /data
comment = Outpost Hyper Backup
transfer logging = yes
log format = OUTPOST_TRANSFER %%o %%b %%l
list = yes
read only = no
auth users = %s
secrets file = /run/outpost/rsync.secrets
munge symlinks = yes
refuse options = copy-links copy-dirlinks keep-dirlinks
`, username)
	return os.WriteFile("/run/outpost/rsyncd.conf", []byte(config), 0600)
}

func netbirdEnv() ([]string, error) {
	management := os.Getenv("NB_MANAGEMENT_URL")
	u, err := url.Parse(management)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return nil, errors.New("NB_MANAGEMENT_URL must be an explicit HTTPS management URL")
	}
	key, err := secret("NB_SETUP_KEY")
	if err != nil {
		return nil, err
	}
	if key == "" {
		if _, err = os.Stat("/state/config.json"); err != nil {
			return nil, errors.New("first enrollment requires NB_SETUP_KEY or NB_SETUP_KEY_FILE")
		}
	}
	env := []string{
		"PATH=/usr/bin", "HOME=/state", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
		"NB_USE_NETSTACK_MODE=true", "NB_ENABLE_NETSTACK_LOCAL_FORWARDING=true",
		"NB_NETSTACK_SKIP_PROXY=true", "NB_DISABLE_DNS=true", "NB_ENABLE_CAPTURE=false",
		"NB_DISABLE_CLIENT_ROUTES=true", "NB_DISABLE_SERVER_ROUTES=true",
		"NB_CONFIG=/state/config.json", "NB_STATE_DIR=/state",
		"NB_DAEMON_ADDR=unix:///state/netbird.sock", "NB_LOG_FILE=console",
		"NB_LOG_LEVEL=warn", "NB_MANAGEMENT_URL=" + management,
		"NB_ALLOW_SERVER_SSH=false", "NB_ALLOW_REMOTE_JOBS=false",
	}
	if key != "" {
		env = append(env, "NB_SETUP_KEY="+key)
	}
	if host := os.Getenv("NB_HOSTNAME"); host != "" {
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`).MatchString(host) {
			return nil, errors.New("invalid NB_HOSTNAME")
		}
		env = append(env, "NB_HOSTNAME="+host)
	}
	return env, nil
}

func child(name string, args []string, env []string, output ...io.Writer) (*exec.Cmd, <-chan error, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	if len(output) > 0 {
		cmd.Stdout = io.MultiWriter(os.Stdout, output[0])
	}
	cmd.Stderr = os.Stderr
	// A process group permits stopping rsync's worker children as well.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return cmd, done, nil
}
func stop(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}
func nbCommand(ctx context.Context, env []string, args ...string) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/netbird", args...)
	cmd.Env = env
	// Enrollment responses are not logged: they can contain identity information.
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
func run(withNetbird bool) error {
	if err := configure(); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	metrics := newMetrics(withNetbird)
	server, metricsDone, err := startMetrics(metrics)
	if err != nil {
		return err
	}
	defer server.Close()
	go metrics.monitor(ctx)
	var nb *exec.Cmd
	var nbDone <-chan error
	if withNetbird {
		env, err := netbirdEnv()
		if err != nil {
			return err
		}
		nb, nbDone, err = child("/usr/bin/netbird", []string{"service", "run"}, env)
		if err != nil {
			return err
		}
		defer stop(nb)
		deadline := time.Now().Add(40 * time.Second)
		live := false
		for time.Now().Before(deadline) {
			probe, closeProbe := context.WithTimeout(ctx, 2*time.Second)
			err = nbCommand(probe, env, "status", "--check", "live")
			closeProbe()
			if err == nil {
				live = true
				break
			}
			select {
			case <-ctx.Done():
				return nil
			case <-nbDone:
				return errors.New("NetBird exited before readiness")
			case <-time.After(time.Second):
			}
		}
		if !live {
			return errors.New("NetBird daemon did not become responsive")
		}
		up, closeUp := context.WithTimeout(ctx, 90*time.Second)
		err = nbCommand(up, env, "up", "--allow-server-ssh=false", "--allow-remote-jobs=false", "--disable-client-routes", "--disable-server-routes", "--disable-dns")
		closeUp()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("NetBird enrollment failed; check management URL, setup key and connectivity")
		}
		ready, closeReady := context.WithTimeout(ctx, 5*time.Second)
		err = nbCommand(ready, env, "status", "--check", "ready")
		closeReady()
		if err != nil {
			return errors.New("NetBird is not ready after enrollment")
		}
		metrics.netbirdReady.Store(true)
		if err = os.Remove("/state/setup-key"); err != nil && !os.IsNotExist(err) {
			return errors.New("cannot remove consumed setup key")
		}
	}
	rs, rsDone, err := child("/usr/bin/rsync", []string{"--daemon", "--no-detach", "--config=/run/outpost/rsyncd.conf"}, []string{"PATH=/usr/bin", "HOME=/data"}, metrics)
	if err != nil {
		return err
	}
	defer stop(rs)
	if err = os.WriteFile("/run/outpost/ready", []byte(fmt.Sprint(withNetbird)), 0600); err != nil {
		return err
	}
	defer os.Remove("/run/outpost/ready")
	metrics.receiverReady.Store(true)
	log.Print("receiver started on loopback TCP 8873; no host port is required")
	select {
	case <-ctx.Done():
		stop(rs)
		stop(nb)
		// Reap supervisors; container PID1 exits after bounded graceful shutdown.
		select {
		case <-rsDone:
		case <-time.After(8 * time.Second):
			_ = syscall.Kill(-rs.Process.Pid, syscall.SIGKILL)
		}
		if nb != nil {
			select {
			case <-nbDone:
			case <-time.After(5 * time.Second):
				_ = syscall.Kill(-nb.Process.Pid, syscall.SIGKILL)
			}
		}
		return nil
	case <-metricsDone:
		return errors.New("metrics server exited; stopping receiver")
	case <-nbDone:
		return errors.New("NetBird exited; stopping receiver")
	case <-rsDone:
		return errors.New("rsync exited; stopping peer")
	}
}
func health() error {
	data, err := os.ReadFile("/run/outpost/ready")
	if err != nil {
		return errors.New("receiver has not started")
	}
	if string(data) == "true" {
		env, err := netbirdEnv()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if err = nbCommand(ctx, env, "status", "--check", "ready"); err != nil {
			return errors.New("NetBird is not ready")
		}
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+rsyncPort, time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "@RSYNCD:") {
		return errors.New("rsync handshake failed")
	}
	return nil
}
