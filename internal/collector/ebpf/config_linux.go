//go:build linux

package ebpf

// shouldIncludeProcess returns true if a process name should be traced.
func (cc *collectorConfig) shouldIncludeProcess(comm string) bool {
	for _, re := range cc.excludeProcessRe {
		if re.MatchString(comm) {
			return false
		}
	}
	if len(cc.processFilterRe) == 0 {
		return true
	}
	for _, re := range cc.processFilterRe {
		if re.MatchString(comm) {
			return true
		}
	}
	return false
}
