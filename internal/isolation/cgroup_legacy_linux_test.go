package isolation

import (
	"strings"
	"testing"
)

func TestProcessIsolationV1RequiresPrivateUnambiguousControllers(t *testing.T) {
	self := "5:memory:/\n4:cpu,cpuacct:/\n3:pids:/\n2:devices:/\n"
	mounts := "24 20 0:5 / /sys/fs/cgroup/memory ro,nosuid - cgroup cgroup rw,memory\n25 20 0:6 / /sys/fs/cgroup/cpu,cpuacct ro,nosuid - cgroup cgroup rw,cpu,cpuacct\n26 20 0:7 / /sys/fs/cgroup/pids ro,nosuid - cgroup cgroup rw,pids\n"
	dirs, e := v1Mounts([]byte(self), []byte(mounts))
	if e != nil || len(dirs) != 3 || dirs["cpu"] != "/sys/fs/cgroup/cpu,cpuacct" {
		t.Fatal(dirs, e)
	}
	for _, row := range []struct{ self, mounts string }{
		{strings.Replace(self, "5:memory:/", "5:memory:/docker/other", 1), mounts},
		{self + "7:memory:/\n", mounts}, {strings.Replace(self, "3:pids:/\n", "", 1), mounts},
		{self, strings.Replace(mounts, "/sys/fs/cgroup/memory", "/tmp/memory", 1)},
		{self, strings.Replace(mounts, "/sys/fs/cgroup/memory", "/sys/fs/cgroup/../memory", 1)},
		{self, strings.Replace(mounts, "0:5 / /sys", "0:5 /ancestor /sys", 1)},
		{self, mounts + strings.Split(mounts, "\n")[0] + "\n"}, {self, "malformed"},
		{"0::/\n", mounts}, {self, strings.Replace(mounts, "rw,pids", "rw,devices", 1)},
	} {
		if _, e := v1Mounts([]byte(row.self), []byte(row.mounts)); e == nil {
			t.Fatal("ambiguous controller accepted", row)
		}
	}
}

func TestProcessIsolationV1MemorySwapAndUnlimitedLimits(t *testing.T) {
	good := map[string]string{"memory": "805306368", "memorySwap": "805306368", "pids": "128", "quota": "100000", "period": "100000"}
	memory, swap, pids, cpu, period, e := v1Limits(good)
	if e != nil || memory != (Limit{"LIMITED", 768 << 20}) || swap != (Limit{"LIMITED", 0}) || pids.Value != 128 || cpu.Value != period || period != 100000 {
		t.Fatal(memory, swap, pids, cpu, period, e)
	}
	for _, row := range []struct{ key, value string }{
		{"memory", ""}, {"memorySwap", ""}, {"memorySwap", "805306367"}, {"period", "0"}, {"period", "max"}, {"quota", "-2"}, {"pids", "0128"},
	} {
		copy := map[string]string{}
		for k, v := range good {
			copy[k] = v
		}
		copy[row.key] = row.value
		if _, _, _, _, _, e := v1Limits(copy); e == nil {
			t.Fatal("invalid control accepted", row)
		}
	}
	for _, sentinel := range []string{"-1", "9223372036854771712"} {
		got, e := v1Memory(sentinel)
		if e != nil || got.State != "UNLIMITED" {
			t.Fatal(got, e)
		}
	}
	good["quota"] = "-1"
	good["pids"] = "max"
	good["memorySwap"] = "9223372036854771712"
	_, swap, pids, cpu, _, e = v1Limits(good)
	if e != nil || swap.State != "UNLIMITED" || pids.State != "UNLIMITED" || cpu.State != "UNLIMITED" {
		t.Fatal(e, swap, pids, cpu)
	}
	good["memorySwap"] = "805306369"
	_, swap, _, _, _, e = v1Limits(good)
	if e != nil || swap.Value != 1 {
		t.Fatal("extra swap allowance lost", swap, e)
	}
}
