// Package cfprefer ports the pure, deterministic core of the Cloudflare
// preferred-IP strategy (~/workspace/cfst-preferred-ip, Python) into Go so
// its decision rules are pinned by tests and reusable from apiserver.
//
// The Python scripts stay the runner: they do the actual probing
// (tcping.py, speed_probe.py), candidate-pool building
// (resolve_candidates.py), Cloudflare DNS updates (cf_update.py), cron and
// the web UI. What is ported here is only the logic that can be decided
// without I/O:
//
//   - the switch decision in cf_update.py (mode=speed): 20% improvement
//     threshold, 1h cooldown, degradation escape hatch;
//   - the latency-watch decision (mode=latency): lowest latency wins, alert
//     when the current IP is missing or lossy;
//   - the CSV result parsing of both cf_update.py and speed_probe.py;
//   - the probe-candidate selection of speed_probe.py: latency top-N with
//     the current IP always forced in as the baseline;
//   - the effective-speed formula of speed_probe.py (fixed 50MB file,
//     10s truncation, speed = downloaded bytes / elapsed);
//   - the Cloudflare official IPv4 range filter of resolve_candidates.py.
//
// Defaults mirror config.env.example: LOSS_MAX=0.2, SPEED_MIN=2.0 MB/s,
// MIN_IMPROVE_RATIO=0.20, UPDATE_COOLDOWN_SECONDS=3600, DOWNLOAD_COUNT=5.
package cfprefer
