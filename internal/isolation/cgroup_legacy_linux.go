package isolation

import (
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// Only the process's private namespace root is supported. Do not guess a host
// cgroup path or treat a missing controller as an unlimited but safe resource.
func v1Mounts(self, mounts []byte) (map[string]string, error) {
	if len(self) == 0 || len(self) > 65536 || len(mounts) == 0 || len(mounts) > 65536 {
		return nil, ErrRequired
	}
	required := map[string]bool{"memory": true, "cpu": true, "pids": true}
	members := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(self), "\n"), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 3 {
			return nil, ErrRequired
		}
		hierarchy, e := limit(fields[0])
		if e != nil || hierarchy.State != "LIMITED" || hierarchy.Value == 0 {
			return nil, ErrRequired
		}
		for _, controller := range strings.Split(fields[1], ",") {
			if !required[controller] {
				continue
			}
			if members[controller] || fields[2] != "/" {
				return nil, ErrRequired
			}
			members[controller] = true
		}
	}
	if len(members) != 3 {
		return nil, ErrRequired
	}
	result := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(mounts), "\n"), "\n") {
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			return nil, ErrRequired
		}
		before, after := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(before) < 6 || len(after) != 3 {
			return nil, ErrRequired
		}
		if after[0] != "cgroup" {
			continue
		}
		for _, controller := range strings.Split(after[2], ",") {
			if !required[controller] {
				continue
			}
			dir := before[4]
			if _, exists := result[controller]; exists || before[3] != "/" || !strings.HasPrefix(dir, "/sys/fs/cgroup/") || path.Clean(dir) != dir || strings.ContainsAny(dir, "\\\x00") {
				return nil, ErrRequired
			}
			result[controller] = dir
		}
	}
	if len(result) != 3 {
		return nil, ErrRequired
	}
	return result, nil
}

func v1Memory(raw string) (Limit, error) {
	if raw == "-1" {
		return Limit{State: "UNLIMITED"}, nil
	}
	v, e := limit(raw)
	if e != nil || v.State != "LIMITED" {
		return Limit{}, ErrRequired
	}
	// Linux exposes a page-aligned LONG_MAX for the v1 unlimited sentinel.
	// Values of an exbibyte or more cannot establish this bounded worker profile.
	if v.Value >= 1<<60 {
		return Limit{State: "UNLIMITED"}, nil
	}
	return v, nil
}

func v1Limits(values map[string]string) (memory, swap, pids, cpu Limit, period uint64, err error) {
	err = ErrRequired
	var e error
	if memory, e = v1Memory(values["memory"]); e != nil {
		return
	}
	total, e := v1Memory(values["memorySwap"])
	if e != nil {
		return
	}
	swap = Limit{State: "UNKNOWN"}
	if total.State == "UNLIMITED" {
		swap = total
	} else if memory.State == "LIMITED" {
		if total.Value < memory.Value {
			return
		}
		// This is additional combined memory+swap allowance, not an assertion that
		// the global v1 kernel reclaimer will never swap a particular physical page.
		swap = Limit{State: "LIMITED", Value: total.Value - memory.Value}
	}
	if pids, e = limit(values["pids"]); e != nil {
		return
	}
	if values["quota"] == "-1" {
		cpu = Limit{State: "UNLIMITED"}
	} else if cpu, e = limit(values["quota"]); e != nil || cpu.State != "LIMITED" {
		return
	}
	parsed, e := limit(values["period"])
	if e != nil || parsed.State != "LIMITED" || parsed.Value == 0 {
		return
	}
	period = parsed.Value
	err = nil
	return
}

func cgroupsV1(o *Observation) {
	self, e := read("/proc/self/cgroup")
	if e != nil {
		return
	}
	mounts, e := read("/proc/self/mountinfo")
	if e != nil {
		return
	}
	roots, e := v1Mounts(self, mounts)
	if e != nil {
		return
	}
	for _, dir := range roots {
		var fs unix.Statfs_t
		if unix.Statfs(dir, &fs) != nil || fs.Type != unix.CGROUP_SUPER_MAGIC {
			return
		}
	}
	values := map[string]string{}
	for _, row := range []struct{ name, controller, file string }{
		{"memory", "memory", "memory.limit_in_bytes"}, {"memorySwap", "memory", "memory.memsw.limit_in_bytes"},
		{"pids", "pids", "pids.max"}, {"quota", "cpu", "cpu.cfs_quota_us"}, {"period", "cpu", "cpu.cfs_period_us"},
	} {
		raw, e := read(roots[row.controller] + "/" + row.file)
		if e != nil {
			return
		}
		values[row.name] = strings.TrimSpace(string(raw))
	}
	memory, swap, pids, cpu, period, e := v1Limits(values)
	if e != nil {
		return
	}
	o.Memory, o.Swap, o.PIDs, o.CPUQuota, o.CPUPeriod = memory, swap, pids, cpu, period
	o.CgroupState, o.CgroupVersion = "OBSERVED", "v1"
}
