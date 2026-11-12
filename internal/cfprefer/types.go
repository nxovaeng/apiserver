package cfprefer

import "time"

// Params are the strategy tunables from config.env.example.
type Params struct {
	// LossMax is the packet-loss ceiling (LOSS_MAX, 0.2 = 20%).
	LossMax float64
	// SpeedMin is the degradation escape floor in MB/s (SPEED_MIN, 2.0).
	SpeedMin float64
	// MinImproveRatio is the required speedup over the current IP before a
	// switch is allowed (MIN_IMPROVE_RATIO, 0.20 = 20%).
	MinImproveRatio float64
	// Cooldown is the minimum interval between DNS updates
	// (UPDATE_COOLDOWN_SECONDS, 3600).
	Cooldown time.Duration
	// ProbeCount is how many lowest-latency candidates enter the download
	// timing round (DOWNLOAD_COUNT, 5).
	ProbeCount int
}

// DefaultParams returns the strategy defaults from config.env.example.
func DefaultParams() Params {
	return Params{
		LossMax:         0.2,
		SpeedMin:        2.0,
		MinImproveRatio: 0.20,
		Cooldown:        time.Hour,
		ProbeCount:      5,
	}
}

// Result is one measured candidate: a row of the speed or latency CSV.
// Columns follow cf_update.parse_csv / speed_probe.parse_latency_csv:
// IP, loss (col 3), latency ms (col 4), download speed MB/s (col 5).
type Result struct {
	IP        string
	Loss      float64
	LatencyMs float64
	SpeedMBs  float64
}

// Decision is the outcome of DecideSpeed. Event matches the history.jsonl
// event names cf_update.py writes.
type Decision struct {
	// Event is one of: "updated", "already_best", "best_speed_zero",
	// "improve_below_threshold", "cooldown", "empty_result".
	Event string
	// TargetIP is the IP to switch to when Event == "updated".
	TargetIP string
	// Degraded is true when the current IP tripped the escape hatch.
	Degraded bool
	// Reason is a human-readable explanation of the decision.
	Reason string
}
