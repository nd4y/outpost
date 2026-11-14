// Package isolation observes kernel-enforced process controls. It does not
// certify host mount ownership, network topology or cold-boot ordering.
package isolation

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const Format = "outpost-process-isolation-1"

var ErrRequired = errors.New("required process isolation unavailable")

type Limit struct {
	State string `json:"state"`
	Value uint64 `json:"value,omitempty"`
}
type Observation struct {
	Format            string            `json:"format"`
	UID               int               `json:"uid"`
	EUID              int               `json:"effectiveUid"`
	GID               int               `json:"gid"`
	EGID              int               `json:"effectiveGid"`
	Groups            []int             `json:"groups"`
	ProcessState      string            `json:"processState"`
	Capabilities      map[string]string `json:"capabilities"`
	NoNewPrivileges   bool              `json:"noNewPrivileges"`
	SeccompFilter     bool              `json:"seccompFilter"`
	RootReadOnly      bool              `json:"rootReadOnly"`
	TemporaryIsolated bool              `json:"temporaryIsolated"`
	TunAbsent         bool              `json:"tunAbsent"`
	NetworkNamespace  uint64            `json:"networkNamespace,omitempty"`
	CgroupState       string            `json:"cgroupState"`
	CgroupVersion     string            `json:"cgroupVersion,omitempty"`
	Memory            Limit             `json:"memory"`
	Swap              Limit             `json:"swap"`
	PIDs              Limit             `json:"pids"`
	CPUQuota          Limit             `json:"cpuQuota"`
	CPUPeriod         uint64            `json:"cpuPeriod,omitempty"`
	Violations        []string          `json:"violations"`
	PendingControls   []string          `json:"pendingControls"`
	RuntimeAcceptance bool              `json:"runtimeAcceptance"`
}

func read(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return nil, ErrRequired
	}
	return b, nil
}
func status(raw []byte) (map[string]string, bool, bool, error) {
	required := map[string]bool{"CapInh": true, "CapPrm": true, "CapEff": true, "CapBnd": true, "CapAmb": true, "NoNewPrivs": true, "Seccomp": true}
	fields := map[string]string{}
	scan := bufio.NewScanner(bytes.NewReader(raw))
	for scan.Scan() {
		parts := strings.SplitN(scan.Text(), ":", 2)
		if len(parts) != 2 || !required[parts[0]] {
			continue
		}
		if _, ok := fields[parts[0]]; ok {
			return nil, false, false, ErrRequired
		}
		fields[parts[0]] = strings.TrimSpace(parts[1])
	}
	if scan.Err() != nil || len(fields) != len(required) {
		return nil, false, false, ErrRequired
	}
	caps := map[string]string{}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		v := fields[name]
		if len(v) != 16 {
			return nil, false, false, ErrRequired
		}
		if _, e := strconv.ParseUint(v, 16, 64); e != nil {
			return nil, false, false, ErrRequired
		}
		caps[name] = v
	}
	if fields["NoNewPrivs"] != "0" && fields["NoNewPrivs"] != "1" {
		return nil, false, false, ErrRequired
	}
	if fields["Seccomp"] != "0" && fields["Seccomp"] != "1" && fields["Seccomp"] != "2" {
		return nil, false, false, ErrRequired
	}
	return caps, fields["NoNewPrivs"] == "1", fields["Seccomp"] == "2", nil
}
func limit(raw string) (Limit, error) {
	if raw == "max" {
		return Limit{State: "UNLIMITED"}, nil
	}
	if raw == "" || strings.TrimSpace(raw) != raw {
		return Limit{}, ErrRequired
	}
	v, e := strconv.ParseUint(raw, 10, 63)
	if e != nil || strconv.FormatUint(v, 10) != raw {
		return Limit{}, ErrRequired
	}
	return Limit{State: "LIMITED", Value: v}, nil
}
func cgroups(o *Observation) {
	o.CgroupState = "UNAVAILABLE"
	o.Memory = Limit{State: "UNKNOWN"}
	o.Swap = o.Memory
	o.PIDs = o.Memory
	o.CPUQuota = o.Memory
	var fs unix.Statfs_t
	if unix.Statfs("/sys/fs/cgroup", &fs) != nil {
		return
	}
	if fs.Type == unix.TMPFS_MAGIC {
		cgroupsV1(o)
		return
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return
	}
	self, e := read("/proc/self/cgroup")
	if e != nil || string(self) != "0::/\n" {
		return
	}
	values := make([]Limit, 0, 3)
	for _, name := range []string{"memory.max", "memory.swap.max", "pids.max"} {
		raw, e := read("/sys/fs/cgroup/" + name)
		if e != nil {
			return
		}
		v, e := limit(strings.TrimSpace(string(raw)))
		if e != nil {
			return
		}
		values = append(values, v)
	}
	raw, e := read("/sys/fs/cgroup/cpu.max")
	if e != nil {
		return
	}
	parts := strings.Fields(string(raw))
	if len(parts) != 2 {
		return
	}
	quota, e := limit(parts[0])
	if e != nil {
		return
	}
	period, e := limit(parts[1])
	if e != nil || period.State != "LIMITED" || period.Value == 0 {
		return
	}
	o.Memory, o.Swap, o.PIDs = values[0], values[1], values[2]
	o.CPUQuota, o.CPUPeriod = quota, period.Value
	o.CgroupState = "OBSERVED"
	o.CgroupVersion = "v2"
}
func Observe() Observation {
	o := Observation{Format: Format, UID: os.Getuid(), EUID: os.Geteuid(), GID: os.Getgid(), EGID: os.Getegid(), ProcessState: "UNAVAILABLE", Capabilities: map[string]string{}, Violations: []string{}, PendingControls: []string{"host-network-separation", "mount-allowlist", "cold-boot-order"}}
	if groups, e := os.Getgroups(); e == nil {
		o.Groups = groups
	} else {
		o.Groups = []int{0}
	}
	var fs unix.Statfs_t
	if unix.Statfs("/proc", &fs) == nil && fs.Type == unix.PROC_SUPER_MAGIC {
		if raw, e := read("/proc/self/status"); e == nil {
			if caps, nnp, seccomp, e := status(raw); e == nil {
				o.Capabilities, o.NoNewPrivileges, o.SeccompFilter = caps, nnp, seccomp
				o.ProcessState = "OBSERVED"
			}
		}
	}
	if unix.Statfs("/", &fs) == nil {
		o.RootReadOnly = fs.Flags&unix.ST_RDONLY != 0
	}
	if unix.Statfs("/tmp", &fs) == nil {
		o.TemporaryIsolated = fs.Type == unix.TMPFS_MAGIC && fs.Flags&unix.ST_RDONLY == 0 && fs.Flags&unix.ST_NOSUID != 0 && fs.Flags&unix.ST_NODEV != 0 && fs.Flags&unix.ST_NOEXEC != 0
	}
	_, e := os.Lstat("/dev/net/tun")
	o.TunAbsent = errors.Is(e, os.ErrNotExist)
	if i, e := os.Stat("/proc/self/ns/net"); e == nil {
		if s, ok := i.Sys().(*syscall.Stat_t); ok {
			o.NetworkNamespace = s.Ino
		}
	}
	cgroups(&o)
	o.Violations = o.violations()
	return o
}
func (o Observation) violations() []string {
	out := []string{}
	if o.UID < 1 || o.EUID < 1 || o.GID < 1 || o.EGID < 1 {
		out = append(out, "ROOT_IDENTITY")
	}
	for _, g := range o.Groups {
		if g == 0 {
			out = append(out, "ROOT_GROUP")
			break
		}
	}
	if o.ProcessState != "OBSERVED" {
		out = append(out, "PROCESS_CONTROLS_UNKNOWN")
	}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if o.Capabilities[name] != "0000000000000000" {
			out = append(out, "CAPABILITIES_PRESENT")
			break
		}
	}
	if !o.NoNewPrivileges {
		out = append(out, "NO_NEW_PRIVILEGES_MISSING")
	}
	if !o.SeccompFilter {
		out = append(out, "SECCOMP_FILTER_MISSING")
	}
	if !o.RootReadOnly {
		out = append(out, "WRITABLE_ROOT")
	}
	if !o.TemporaryIsolated {
		out = append(out, "TEMPORARY_FILESYSTEM_UNSAFE")
	}
	if !o.TunAbsent {
		out = append(out, "TUN_NOT_ABSENT")
	}
	if o.CgroupState != "OBSERVED" {
		out = append(out, "RESOURCE_CONTROLS_UNKNOWN")
	}
	for _, row := range []struct {
		name  string
		value Limit
	}{{"MEMORY", o.Memory}, {"PIDS", o.PIDs}, {"CPU", o.CPUQuota}} {
		if row.value.State != "LIMITED" || row.value.Value == 0 {
			out = append(out, row.name+"_UNBOUNDED")
		}
	}
	if o.CPUPeriod == 0 {
		out = append(out, "CPU_PERIOD_UNKNOWN")
	}
	if o.Swap.State != "LIMITED" || o.Swap.Value != 0 {
		out = append(out, "SWAP_ENABLED_OR_UNKNOWN")
	}
	return out
}
func (o Observation) Check() error {
	if missing := o.violations(); len(missing) != 0 {
		return fmt.Errorf("%w: %s", ErrRequired, strings.Join(missing, ","))
	}
	return nil
}
