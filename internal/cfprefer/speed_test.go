package cfprefer_test

import (
	"testing"

	"xray-panel-server/internal/cfprefer"
)

func TestEffectiveSpeedMBs(t *testing.T) {
	const mib = 1048576.0
	tests := []struct {
		name      string
		sizeBytes float64
		seconds   float64
		code      string
		want      float64
	}{
		{"50MiB in 5s", 50 * mib, 5, "200", 10},
		{"206 partial counts", 25 * mib, 5, "206", 5},
		{"truncated at 10s cap", 20 * mib, 10, "200", 2},
		{"http error is zero", 50 * mib, 5, "404", 0},
		{"zero elapsed is zero", 50 * mib, 0, "200", 0},
		{"negative elapsed is zero", 50 * mib, -1, "200", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cfprefer.EffectiveSpeedMBs(tc.sizeBytes, tc.seconds, tc.code); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
