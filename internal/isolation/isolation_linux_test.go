package isolation

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestProcessIsolationRejectsUnknownAndUnboundedControls(t *testing.T) {
	safe := Observation{UID: 65532, EUID: 65532, GID: 65532, EGID: 65532, Groups: []int{65532}, ProcessState: "OBSERVED", Capabilities: map[string]string{}, NoNewPrivileges: true, SeccompFilter: true, RootReadOnly: true, TemporaryIsolated: true, TunAbsent: true, CgroupState: "OBSERVED", Memory: Limit{"LIMITED", 768 << 20}, Swap: Limit{"LIMITED", 0}, PIDs: Limit{"LIMITED", 128}, CPUQuota: Limit{"LIMITED", 100000}, CPUPeriod: 100000}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		safe.Capabilities[name] = "0000000000000000"
	}
	if e := safe.Check(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Observation){
		func(o *Observation) { o.UID = 0 }, func(o *Observation) { o.EUID = -1 }, func(o *Observation) { o.CPUPeriod = 0 }, func(o *Observation) { o.Groups = []int{0} }, func(o *Observation) { o.ProcessState = "UNAVAILABLE" },
		func(o *Observation) { o.Capabilities = map[string]string{} }, func(o *Observation) { o.NoNewPrivileges = false }, func(o *Observation) { o.SeccompFilter = false },
		func(o *Observation) { o.RootReadOnly = false }, func(o *Observation) { o.TemporaryIsolated = false }, func(o *Observation) { o.TunAbsent = false },
		func(o *Observation) { o.CgroupState = "UNAVAILABLE" }, func(o *Observation) { o.Memory = Limit{"UNLIMITED", 0} }, func(o *Observation) { o.PIDs = Limit{"UNKNOWN", 0} },
		func(o *Observation) { o.CPUQuota = Limit{"LIMITED", 0} }, func(o *Observation) { o.Swap = Limit{"LIMITED", 1} },
	} {
		copy := safe
		change(&copy)
		if !errors.Is(copy.Check(), ErrRequired) {
			t.Fatal("unsafe observation accepted")
		}
	}
}
func TestProcessIsolationStatusParserFailsClosed(t *testing.T) {
	good := "CapInh: 0000000000000000\nCapPrm: 0000000000000000\nCapEff: 0000000000000000\nCapBnd: 0000000000000000\nCapAmb: 0000000000000000\nNoNewPrivs: 1\nSeccomp: 2\n"
	caps, nnp, seccomp, e := status([]byte(good))
	if e != nil || len(caps) != 5 || !nnp || !seccomp {
		t.Fatal(e)
	}
	for _, bad := range []string{good + "CapEff: 0000000000000000\n", strings.Replace(good, "CapBnd:", "Missing:", 1), strings.Replace(good, "NoNewPrivs: 1", "NoNewPrivs: 2", 1), strings.Replace(good, "0000000000000000", "invalid", 1)} {
		if _, _, _, e := status([]byte(bad)); e == nil {
			t.Fatal("malformed kernel observation accepted")
		}
	}
	for _, bad := range []string{"", "-1", "01", "18446744073709551615", "1 2"} {
		if _, e := limit(bad); e == nil {
			t.Fatal("invalid limit accepted", bad)
		}
	}
	for _, value := range []string{"0", "1", "768000000", "max"} {
		if _, e := limit(value); e != nil {
			t.Fatal(e)
		}
	}
}
func TestProcessIsolationObservesActualKernelWithoutClaimingRuntimeAcceptance(t *testing.T) {
	o := Observe()
	if o.Format != Format || o.UID != os.Getuid() || o.EUID != os.Geteuid() || o.RuntimeAcceptance || len(o.PendingControls) != 3 {
		t.Fatal(o)
	}
	if o.ProcessState != "OBSERVED" || len(o.Capabilities) != 5 || o.NetworkNamespace == 0 {
		t.Fatal("kernel observations unavailable", o)
	}
	if (o.Check() == nil) != (len(o.Violations) == 0) {
		t.Fatal("inconsistent check")
	}
	raw, e := json.Marshal(o)
	if e != nil || strings.Contains(string(raw), "/proc/") || strings.Contains(string(raw), "/sys/") {
		t.Fatal("raw host paths escaped", e)
	}
}
