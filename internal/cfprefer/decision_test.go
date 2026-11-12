package cfprefer_test

import (
	"strings"
	"testing"
	"time"

	"xray-panel-server/internal/cfprefer"
)

func TestDecideSpeed(t *testing.T) {
	now := time.Date(2026, 11, 12, 22, 0, 0, 0, time.UTC)
	p := cfprefer.DefaultParams()
	r := func(ip string, loss, latency, speed float64) cfprefer.Result {
		return cfprefer.Result{IP: ip, Loss: loss, LatencyMs: latency, SpeedMBs: speed}
	}

	tests := []struct {
		name         string
		rows         []cfprefer.Result
		current      string
		lastUpdate   time.Time
		wantEvent    string
		wantTarget   string
		wantDegraded bool
	}{
		{
			name:      "empty rows",
			rows:      nil,
			wantEvent: "empty_result",
		},
		{
			name:      "best speed zero",
			rows:      []cfprefer.Result{r("1.1.1.1", 0, 90, 0), r("1.0.0.1", 0, 80, 0)},
			wantEvent: "best_speed_zero",
		},
		{
			name:      "already best even when current is slow",
			rows:      []cfprefer.Result{r("1.1.1.1", 0, 90, 1.0), r("1.0.0.1", 0, 80, 0.5)},
			current:   "1.1.1.1",
			wantEvent: "already_best",
		},
		{
			name:         "degraded current unreachable bypasses cooldown",
			rows:         []cfprefer.Result{r("1.1.1.1", 0, 90, 10)},
			current:      "2.2.2.2",
			lastUpdate:   now.Add(-10 * time.Minute),
			wantEvent:    "updated",
			wantTarget:   "1.1.1.1",
			wantDegraded: true,
		},
		{
			name:         "degraded loss over max",
			rows:         []cfprefer.Result{r("1.1.1.1", 0, 90, 10), r("2.2.2.2", 0.21, 80, 9)},
			current:      "2.2.2.2",
			lastUpdate:   now.Add(-10 * time.Minute),
			wantEvent:    "updated",
			wantTarget:   "1.1.1.1",
			wantDegraded: true,
		},
		{
			name:       "loss exactly at max is not degraded",
			rows:       []cfprefer.Result{r("1.1.1.1", 0, 90, 12), r("2.2.2.2", 0.2, 80, 10)},
			current:    "2.2.2.2",
			wantEvent:  "updated",
			wantTarget: "1.1.1.1",
		},
		{
			name:         "degraded current speed zero bypasses threshold",
			rows:         []cfprefer.Result{r("1.1.1.1", 0, 90, 0.5), r("2.2.2.2", 0, 80, 0)},
			current:      "2.2.2.2",
			wantEvent:    "updated",
			wantTarget:   "1.1.1.1",
			wantDegraded: true,
		},
		{
			name:         "cliff drop below speed min with best at twice min",
			rows:         []cfprefer.Result{r("1.1.1.1", 0, 90, 4.0), r("2.2.2.2", 0, 80, 1.5)},
			current:      "2.2.2.2",
			lastUpdate:   now.Add(-10 * time.Minute),
			wantEvent:    "updated",
			wantTarget:   "1.1.1.1",
			wantDegraded: true,
		},
		{
			name:       "cliff not triggered when best below twice min, cooldown applies",
			rows:       []cfprefer.Result{r("1.1.1.1", 0, 90, 3.9), r("2.2.2.2", 0, 80, 1.5)},
			current:    "2.2.2.2",
			lastUpdate: now.Add(-10 * time.Minute),
			wantEvent:  "cooldown",
		},
		{
			name:      "improvement below twenty percent rejected",
			rows:      []cfprefer.Result{r("1.1.1.1", 0, 90, 11.9), r("2.2.2.2", 0, 80, 10)},
			current:   "2.2.2.2",
			wantEvent: "improve_below_threshold",
		},
		{
			name:       "improvement exactly twenty percent allowed",
			rows:       []cfprefer.Result{r("1.1.1.1", 0, 90, 12.0), r("2.2.2.2", 0, 80, 10)},
			current:    "2.2.2.2",
			wantEvent:  "updated",
			wantTarget: "1.1.1.1",
		},
		{
			name:       "cooldown blocks healthy switch",
			rows:       []cfprefer.Result{r("1.1.1.1", 0, 90, 15), r("2.2.2.2", 0, 80, 10)},
			current:    "2.2.2.2",
			lastUpdate: now.Add(-30 * time.Minute),
			wantEvent:  "cooldown",
		},
		{
			name:       "cooldown expired allows switch",
			rows:       []cfprefer.Result{r("1.1.1.1", 0, 90, 15), r("2.2.2.2", 0, 80, 10)},
			current:    "2.2.2.2",
			lastUpdate: now.Add(-61 * time.Minute),
			wantEvent:  "updated",
			wantTarget: "1.1.1.1",
		},
		{
			name:       "first run with no current ip",
			rows:       []cfprefer.Result{r("1.1.1.1", 0, 90, 10), r("1.0.0.1", 0, 80, 5)},
			wantEvent:  "updated",
			wantTarget: "1.1.1.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cfprefer.DecideSpeed(tc.rows, tc.current, tc.lastUpdate, now, p)
			if got.Event != tc.wantEvent {
				t.Fatalf("Event = %q, want %q (reason: %s)", got.Event, tc.wantEvent, got.Reason)
			}
			if got.TargetIP != tc.wantTarget {
				t.Errorf("TargetIP = %q, want %q", got.TargetIP, tc.wantTarget)
			}
			if got.Degraded != tc.wantDegraded {
				t.Errorf("Degraded = %v, want %v", got.Degraded, tc.wantDegraded)
			}
			if got.Reason == "" {
				t.Errorf("Reason must not be empty")
			}
		})
	}
}

func TestDecideLatency(t *testing.T) {
	p := cfprefer.DefaultParams()
	rows := []cfprefer.Result{
		{IP: "1.1.1.1", Loss: 0, LatencyMs: 90},
		{IP: "1.0.0.1", Loss: 0, LatencyMs: 80},
		{IP: "2.2.2.2", Loss: 0.3, LatencyMs: 70},
	}

	best, alert, ok := cfprefer.DecideLatency(rows, "1.1.1.1", p)
	if !ok || best.IP != "2.2.2.2" {
		t.Fatalf("best = %+v ok=%v, want lowest latency 2.2.2.2", best, ok)
	}
	if alert != "" {
		t.Errorf("healthy current must not alert, got %q", alert)
	}

	_, alert, _ = cfprefer.DecideLatency(rows, "2.2.2.2", p)
	if alert == "" || !strings.Contains(alert, "2.2.2.2") {
		t.Errorf("lossy current must alert, got %q", alert)
	}

	_, alert, _ = cfprefer.DecideLatency(rows, "9.9.9.9", p)
	if alert == "" {
		t.Errorf("missing current must alert")
	}

	_, _, ok = cfprefer.DecideLatency(nil, "1.1.1.1", p)
	if ok {
		t.Errorf("empty rows must return ok=false")
	}
}
