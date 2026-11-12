package cfprefer_test

import (
	"testing"

	"xray-panel-server/internal/cfprefer"
)

func TestSelectProbeCandidates(t *testing.T) {
	valid := []cfprefer.Result{
		{IP: "10.0.0.1", Loss: 0, LatencyMs: 70},
		{IP: "10.0.0.2", Loss: 0, LatencyMs: 80},
		{IP: "10.0.0.3", Loss: 0, LatencyMs: 90},
		{IP: "10.0.0.4", Loss: 0, LatencyMs: 100},
		{IP: "10.0.0.5", Loss: 0, LatencyMs: 110},
		{IP: "10.0.0.6", Loss: 0, LatencyMs: 120},
		{IP: "10.0.0.7", Loss: 0, LatencyMs: 130},
	}
	all := map[string]cfprefer.Result{}
	for _, r := range valid {
		all[r.IP] = r
	}

	// Top 5 by latency, no current IP.
	got := cfprefer.SelectProbeCandidates(valid, all, 5, "")
	if len(got) != 5 || got[4].IP != "10.0.0.5" {
		t.Fatalf("top-5 = %+v", got)
	}

	// Current IP inside the top 5 is just marked, not duplicated.
	got = cfprefer.SelectProbeCandidates(valid, all, 5, "10.0.0.3")
	if len(got) != 5 {
		t.Fatalf("len = %d, want 5", len(got))
	}
	if !got[2].IsCurrent {
		t.Errorf("10.0.0.3 must be marked current: %+v", got)
	}

	// Current IP below the top 5 is forced in with its real measurements.
	got = cfprefer.SelectProbeCandidates(valid, all, 5, "10.0.0.7")
	if len(got) != 6 {
		t.Fatalf("len = %d, want 6", len(got))
	}
	last := got[5]
	if last.IP != "10.0.0.7" || !last.IsCurrent || last.LatencyMs != 130 {
		t.Errorf("forced-in current = %+v", last)
	}

	// Current IP absent from the latency round is appended with 0/0.
	got = cfprefer.SelectProbeCandidates(valid, all, 5, "10.9.9.9")
	if len(got) != 6 {
		t.Fatalf("len = %d, want 6", len(got))
	}
	last = got[5]
	if last.IP != "10.9.9.9" || !last.IsCurrent || last.Loss != 0 || last.LatencyMs != 0 {
		t.Errorf("unknown current = %+v, want loss/latency 0", last)
	}

	// count 0 falls back to the default (5).
	got = cfprefer.SelectProbeCandidates(valid, all, 0, "")
	if len(got) != 5 {
		t.Fatalf("default count len = %d, want 5", len(got))
	}
}
