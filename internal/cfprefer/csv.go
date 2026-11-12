package cfprefer

import (
	"encoding/csv"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ParseSpeedCSV mirrors cf_update.parse_csv: skip the header row, skip rows
// with fewer than 6 columns, parse IP (col 0), loss (col 3), latency (col 4)
// and speed (col 5, empty means 0.0); rows with unparsable numbers are
// skipped.
func ParseSpeedCSV(r io.Reader) ([]Result, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // Python csv tolerates ragged rows; skip them below
	records, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	var rows []Result
	for i, rec := range records {
		if i == 0 || len(rec) < 6 {
			continue
		}
		ip := strings.TrimSpace(rec[0])
		loss, err := strconv.ParseFloat(strings.TrimSpace(rec[3]), 64)
		if err != nil {
			continue
		}
		latency, err := strconv.ParseFloat(strings.TrimSpace(rec[4]), 64)
		if err != nil {
			continue
		}
		speed := 0.0
		if s := strings.TrimSpace(rec[5]); s != "" {
			speed, err = strconv.ParseFloat(s, 64)
			if err != nil {
				continue
			}
		}
		rows = append(rows, Result{IP: ip, Loss: loss, LatencyMs: latency, SpeedMBs: speed})
	}
	return rows, nil
}

// ParseLatencyCSV mirrors speed_probe.parse_latency_csv: skip the header row
// and rows with fewer than 5 columns, skip empty IPs and rows with
// unparsable numbers. It returns the loss-acceptable candidates sorted by
// latency ascending, plus an index of every row by IP (including the ones
// filtered out by loss, so the current IP can still be forced in).
func ParseLatencyCSV(r io.Reader, lossMax float64) (valid []Result, all map[string]Result, err error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // Python csv tolerates ragged rows; skip them below
	records, err := cr.ReadAll()
	if err != nil {
		return nil, nil, err
	}
	all = map[string]Result{}
	for i, rec := range records {
		if i == 0 || len(rec) < 5 {
			continue
		}
		ip := strings.TrimSpace(rec[0])
		if ip == "" {
			continue
		}
		loss, err := strconv.ParseFloat(strings.TrimSpace(rec[3]), 64)
		if err != nil {
			continue
		}
		latency, err := strconv.ParseFloat(strings.TrimSpace(rec[4]), 64)
		if err != nil {
			continue
		}
		info := Result{IP: ip, Loss: loss, LatencyMs: latency}
		all[ip] = info
		if loss <= lossMax {
			valid = append(valid, info)
		}
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].LatencyMs < valid[j].LatencyMs })
	return valid, all, nil
}
