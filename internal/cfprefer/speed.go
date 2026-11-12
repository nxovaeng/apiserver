package cfprefer

const bytesPerMiB = 1048576.0

// EffectiveSpeedMBs mirrors the speed formula in speed_probe.probe_one:
// downloaded bytes / elapsed seconds, in MiB/s. Only HTTP 200/206 with a
// positive elapsed time count; anything else (HTTP error, timeout, curl
// crash) is 0. A download truncated by --max-time still counts by the
// bytes actually downloaded over the elapsed time.
func EffectiveSpeedMBs(sizeBytes, seconds float64, httpCode string) float64 {
	if (httpCode != "200" && httpCode != "206") || seconds <= 0 {
		return 0
	}
	return sizeBytes / seconds / bytesPerMiB
}
