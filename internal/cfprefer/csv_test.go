package cfprefer_test

import (
	"strings"
	"testing"

	"xray-panel-server/internal/cfprefer"
)

func TestParseSpeedCSV(t *testing.T) {
	// Columns mirror the CSV cf_update.py / speed_probe.py write:
	// IP, sent, received, loss, latency, speed, region.
	in := `IP 地址,已发送,已接收,丢包率,平均延迟,下载速度 (MB/s),地区码
104.16.0.1,4,4,0.0,82.5,12.34,
104.17.0.1,4,4,0.1,95.0,,,
104.18.0.1,4,4
104.19.0.1,4,4,not-a-number,90.0,5.0,
 104.20.0.1 ,4,4,0.0, 88.0 , 7.5 ,
`
	rows, err := cfprefer.ParseSpeedCSV(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseSpeedCSV: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3: %+v", len(rows), rows)
	}
	if rows[0].IP != "104.16.0.1" || rows[0].Loss != 0 || rows[0].LatencyMs != 82.5 || rows[0].SpeedMBs != 12.34 {
		t.Errorf("row 0 = %+v", rows[0])
	}
	// Empty speed column means 0.0, not a skipped row.
	if rows[1].IP != "104.17.0.1" || rows[1].SpeedMBs != 0 {
		t.Errorf("row 1 = %+v, want empty speed as 0", rows[1])
	}
	// Whitespace is trimmed.
	if rows[2].IP != "104.20.0.1" || rows[2].LatencyMs != 88.0 || rows[2].SpeedMBs != 7.5 {
		t.Errorf("row 2 = %+v", rows[2])
	}
}

func TestParseLatencyCSV(t *testing.T) {
	in := `IP 地址,已发送,已接收,丢包率,平均延迟,下载速度 (MB/s),地区码
104.16.0.1,4,4,0.0,90.0,,
104.17.0.1,4,4,0.3,70.0,,
104.18.0.1,4,4,0.0,80.0,,
,4,4,0.0,60.0,,
104.19.0.1,4,4
`
	valid, all, err := cfprefer.ParseLatencyCSV(strings.NewReader(in), 0.2)
	if err != nil {
		t.Fatalf("ParseLatencyCSV: %v", err)
	}
	// Lossy 104.17.0.1 is excluded from valid but kept in the index.
	if len(valid) != 2 {
		t.Fatalf("got %d valid rows, want 2: %+v", len(valid), valid)
	}
	if valid[0].IP != "104.18.0.1" || valid[1].IP != "104.16.0.1" {
		t.Errorf("valid must be sorted by latency ascending: %+v", valid)
	}
	if _, ok := all["104.17.0.1"]; !ok {
		t.Errorf("lossy IP must stay in the all-by-IP index")
	}
	if len(all) != 3 {
		t.Errorf("all = %d entries, want 3", len(all))
	}
}
