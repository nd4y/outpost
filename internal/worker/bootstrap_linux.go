package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/nd4y/outpost/internal/recovery"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

const BootstrapFormat = "outpost-bootstrap-2"

// Bootstrap is local-only. It cannot be supplied or expanded by a remote job.
type Bootstrap struct {
	Volume          volume.Binding    `json:"volume"`
	Format          string            `json:"format"`
	Directory       string            `json:"directory"`
	Node            string            `json:"node"`
	Owner           ed25519.PublicKey `json:"ownerPublicKey"`
	CertificateFile string            `json:"certificateFile"`
	PrivateKeyFile  string            `json:"privateKeyFile"`
	CAFile          string            `json:"caFile"`
	StorageCAFile   string            `json:"storageCAFile,omitempty"`
	ControlEndpoint string            `json:"controlEndpoint,omitempty"`
	ControlIdentity string            `json:"controlIdentity,omitempty"`
	Listen          string            `json:"listen,omitempty"`
	Credentials     map[string]string `json:"credentialFiles"`
}

// ReadPrivate never follows a final symlink, opens a device/FIFO, or accepts a
// world/group-readable secret. Errors are classified before reaching the CLI.
func ReadPrivate(path string, limit int) ([]byte, error) {
	if !filepath.IsAbs(path) || limit < 1 || limit > 64<<20 {
		return nil, ErrDenied
	}
	r, e := localfs.OpenRoot(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer r.Close()
	f, e := localfs.OpenFile(r, filepath.Base(path), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() < 1 || i.Size() > int64(limit) {
		return nil, ErrDenied
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) != i.Size() {
		return nil, ErrDenied
	}
	return b, nil
}
func DecodeInput(raw []byte, out any, max int) error {
	if len(raw) == 0 || len(raw) > max {
		return ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrDenied
	}
	return nil
}
func LoadBootstrap(path string) (Bootstrap, error) {
	var b Bootstrap
	raw, e := ReadPrivate(path, 65536)
	if e != nil {
		return b, e
	}
	if DecodeInput(raw, &b, 65536) != nil || b.Format != BootstrapFormat || b.Volume.Scope != b.Node || !filepath.IsAbs(b.Directory) || !storage.ID(b.Node) || len(b.Owner) != 32 || len(b.Credentials) > 128 {
		return b, ErrDenied
	}
	if b.Listen != "" {
		host, port, e := net.SplitHostPort(b.Listen)
		if e != nil || net.ParseIP(host) == nil || port == "" {
			return b, ErrDenied
		}
	}
	for id, file := range b.Credentials {
		if !storage.ID(id) || !filepath.IsAbs(file) {
			return b, ErrDenied
		}
	}
	if b.ControlEndpoint == "" && b.ControlIdentity != "" || b.ControlEndpoint != "" && !storage.ID(b.ControlIdentity) {
		return b, ErrDenied
	}
	return b, nil
}
func (b Bootstrap) TLS() (tls.Certificate, *x509.CertPool, error) {
	cert, e := ReadPrivate(b.CertificateFile, 65536)
	if e != nil {
		return tls.Certificate{}, nil, e
	}
	key, e := ReadPrivate(b.PrivateKeyFile, 65536)
	if e != nil {
		return tls.Certificate{}, nil, e
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return pair, nil, e
	}
	ca, e := ReadPrivate(b.CAFile, 65536)
	if e != nil {
		return pair, nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return pair, nil, ErrDenied
	}
	return pair, roots, nil
}
func (b Bootstrap) Open(initialize bool) (*Worker, func(), error) { return b.open(initialize, nil) }

// OpenTrusted is explicit local enrollment; ordinary Open never loads recovery keys.
func (b Bootstrap) OpenTrusted(x *recovery.Executor) (*Worker, func(), error) {
	if x == nil || x.NodeIdentity() != b.Node {
		return nil, nil, ErrDenied
	}
	return b.open(false, x)
}
func (b Bootstrap) open(initialize bool, x *recovery.Executor) (*Worker, func(), error) {
	if b.Format != BootstrapFormat || b.Volume.Scope != b.Node {
		return nil, nil, ErrDenied
	}
	if e := b.Volume.Check(context.Background(), b.Directory, initialize); e != nil {
		return nil, nil, e
	}

	cert, roots, e := b.TLS()
	if e != nil {
		return nil, nil, e
	}
	var fetcher *control.Fetcher
	if b.ControlEndpoint != "" {
		fetcher, e = control.NewFetcher(b.ControlEndpoint, b.ControlIdentity, b.Node, cert, roots, 5*time.Second)
		if e != nil {
			return nil, nil, e
		}
	}
	root, e := b.Volume.Open(context.Background(), b.Directory, initialize)
	if e != nil {
		if fetcher != nil {
			fetcher.Close()
		}
		return nil, nil, e
	}
	// The guard owns this descriptor until cleanup; Worker keeps its own clone.
	w, e := Open(Options{Recovery: x, Root: root, Guard: func(ctx context.Context) error { return b.Volume.CheckHandle(ctx, b.Directory, root) }, Directory: b.Directory, Node: b.Node, Owner: b.Owner, Certificate: cert, Roots: roots, Initialize: initialize, Fetcher: fetcher, Resolve: b.Resolve})
	if e != nil {
		root.Close()
		if fetcher != nil {
			fetcher.Close()
		}
		return nil, nil, e
	}
	return w, func() {
		w.Close()
		root.Close()
		if fetcher != nil {
			fetcher.Close()
		}
	}, nil
}
func (b Bootstrap) Resolve(ctx context.Context, p storage.Profile) (*storage.Backend, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	file, ok := b.Credentials[p.ID()]
	if !ok {
		return nil, ErrDenied
	}
	raw, e := ReadPrivate(file, 65536)
	if e != nil {
		return nil, ErrDenied
	}
	var c struct {
		Access       string `json:"access"`
		Secret       string `json:"secret"`
		SessionToken string `json:"sessionToken,omitempty"`
		ExpiresUnix  int64  `json:"expiresUnix"`
	}
	if DecodeInput(raw, &c, 65536) != nil {
		return nil, ErrDenied
	}
	var roots *x509.CertPool
	if b.StorageCAFile != "" {
		pem, e := ReadPrivate(b.StorageCAFile, 65536)
		if e != nil {
			return nil, ErrDenied
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, ErrDenied
		}
	}
	return storage.New(p, storage.Credentials{Access: c.Access, Secret: c.Secret, SessionToken: c.SessionToken, ExpiresUnix: c.ExpiresUnix}, roots)
}
