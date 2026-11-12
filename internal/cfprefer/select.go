package cfprefer

// Candidate is a probe target selected for the download timing round.
type Candidate struct {
	Result
	// IsCurrent marks the IP currently in use, forced into the round as
	// the real-throughput baseline even when its latency fell out of the
	// top-N.
	IsCurrent bool
}

// SelectProbeCandidates mirrors the selection in speed_probe.main: take the
// lowest-latency valid candidates up to count (valid must already be sorted
// by latency ascending, as ParseLatencyCSV returns), then force the current
// IP in when it is not among them. A current IP absent from the latency
// round entirely is appended with loss/latency 0, matching the Python
// fallback. When count is 0 or negative, DefaultParams().ProbeCount is used.
func SelectProbeCandidates(valid []Result, all map[string]Result, count int, currentIP string) []Candidate {
	if count <= 0 {
		count = DefaultParams().ProbeCount
	}
	if count > len(valid) {
		count = len(valid)
	}
	selected := make([]Candidate, 0, count+1)
	for _, r := range valid[:count] {
		selected = append(selected, Candidate{Result: r})
	}
	if currentIP == "" {
		return selected
	}
	for i := range selected {
		if selected[i].IP == currentIP {
			selected[i].IsCurrent = true
			return selected
		}
	}
	cur, ok := all[currentIP]
	if !ok {
		cur = Result{IP: currentIP, Loss: 0, LatencyMs: 0}
	}
	return append(selected, Candidate{Result: cur, IsCurrent: true})
}
