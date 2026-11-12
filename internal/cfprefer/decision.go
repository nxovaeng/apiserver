package cfprefer

import (
	"fmt"
	"time"
)

// DecideSpeed mirrors the mode=speed branch of cf_update.py main().
// rows are the parsed speed CSV, currentIP is the IP in state/current.json
// ("" on first run), lastUpdate is state.updated_at (zero when unknown),
// now is the current time, p carries the strategy tunables.
//
// Order matters and is kept identical to the Python original:
//  1. empty rows -> empty_result
//  2. best speed <= 0 -> best_speed_zero
//  3. best is already the current IP -> already_best
//  4. degraded current IP (unreachable, loss over max, speed 0, or a
//     cliff drop below SPEED_MIN while the best is >= 2*SPEED_MIN)
//     bypasses both the improvement threshold and the cooldown
//  5. healthy current IP: best must beat it by MinImproveRatio
//  6. healthy current IP: cooldown since lastUpdate
//  7. otherwise the switch is allowed -> updated
func DecideSpeed(rows []Result, currentIP string, lastUpdate, now time.Time, p Params) Decision {
	if len(rows) == 0 {
		return Decision{Event: "empty_result", Reason: "结果数据为空，本轮跳过"}
	}

	best := rows[0]
	for _, r := range rows[1:] {
		if r.SpeedMBs > best.SpeedMBs {
			best = r
		}
	}
	if best.SpeedMBs <= 0 {
		return Decision{Event: "best_speed_zero", Reason: "最优 IP 下载速度为 0，本轮不更新"}
	}

	if currentIP != "" && currentIP == best.IP {
		return Decision{
			Event:  "already_best",
			Reason: fmt.Sprintf("当前在用 IP %s 依然是最优选择 (%.2f MB/s)，维持不变", best.IP, best.SpeedMBs),
		}
	}

	var cur *Result
	for i := range rows {
		if rows[i].IP == currentIP {
			cur = &rows[i]
			break
		}
	}

	degraded := false
	reason := ""
	if currentIP != "" {
		switch {
		case cur == nil:
			degraded = true
			reason = fmt.Sprintf("当前在用 IP %s 彻底无法连通 (丢包或超时)", currentIP)
		case cur.Loss > p.LossMax:
			degraded = true
			reason = fmt.Sprintf("当前在用 IP %s 丢包率超标 (%.0f%% > %.0f%%)", currentIP, cur.Loss*100, p.LossMax*100)
		case cur.SpeedMBs <= 0:
			degraded = true
			reason = fmt.Sprintf("当前在用 IP %s 下载失败 (速度=0)", currentIP)
		case cur.SpeedMBs < p.SpeedMin && best.SpeedMBs >= p.SpeedMin*2:
			degraded = true
			reason = fmt.Sprintf("当前在用 IP %s 速度发生断崖式下跌 (%.2f < %.1f MB/s)", currentIP, cur.SpeedMBs, p.SpeedMin)
		}
	}

	if !degraded && cur != nil && cur.SpeedMBs > 0 {
		if best.SpeedMBs < cur.SpeedMBs*(1.0+p.MinImproveRatio) {
			return Decision{
				Event:  "improve_below_threshold",
				Reason: fmt.Sprintf("新最优 %s (%.2f MB/s) 对比当前在用 %s (%.2f MB/s) 提速不足 %.0f%%，保持当前解析避免抖动", best.IP, best.SpeedMBs, currentIP, cur.SpeedMBs, p.MinImproveRatio*100),
			}
		}
	}

	if !degraded && !lastUpdate.IsZero() && now.Sub(lastUpdate) < p.Cooldown {
		remaining := int(p.Cooldown - now.Sub(lastUpdate))
		return Decision{
			Event:  "cooldown",
			Reason: fmt.Sprintf("处于更新冷却期 (剩余 %ds) 且当前在用 IP 健康，本轮不更新", remaining),
		}
	}

	d := Decision{Event: "updated", TargetIP: best.IP, Degraded: degraded}
	if degraded {
		d.Reason = "触发应急逃生: " + reason + "，立即放行更新!"
	} else {
		d.Reason = fmt.Sprintf("切换到 %s (%.2f MB/s, %.1fms)", best.IP, best.SpeedMBs, best.LatencyMs)
	}
	return d
}

// DecideLatency mirrors the mode=latency branch of cf_update.py main().
// It never updates DNS: it returns the lowest-latency candidate and an
// alert string when the current IP is missing from the round or its loss
// exceeds LossMax ("" when healthy). ok is false when rows is empty.
func DecideLatency(rows []Result, currentIP string, p Params) (best Result, alert string, ok bool) {
	if len(rows) == 0 {
		return Result{}, "", false
	}
	best = rows[0]
	for _, r := range rows[1:] {
		if r.LatencyMs < best.LatencyMs {
			best = r
		}
	}
	if currentIP == "" {
		return best, "", true
	}
	var cur *Result
	for i := range rows {
		if rows[i].IP == currentIP {
			cur = &rows[i]
			break
		}
	}
	if cur == nil || cur.Loss > p.LossMax {
		alert = fmt.Sprintf("当前在用 IP %s 在本轮延迟结果中缺失或丢包率超标 (>%.0f%%)", currentIP, p.LossMax*100)
	}
	return best, alert, true
}
