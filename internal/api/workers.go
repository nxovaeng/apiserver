package api

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"xray-panel-server/internal/logger"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/system"
	"xray-panel-server/internal/xray"
)

func (s *Server) startTrafficSync() {
	interval := 60 * time.Second
	apiClient := xray.NewAPIClientWithBinary(
		s.config.Xray.APIPort,
		s.config.Xray.BinaryPath,
	)

	go func() {
		select {
		case <-s.stopCh:
			return
		case <-time.After(10 * time.Second):
		}

		logger.Debug("Traffic sync worker started (interval: %v)", interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.syncTraffic(apiClient)
			}
		}
	}()
}

func (s *Server) syncTraffic(client *xray.APIClient) {
	if !client.IsHealthy() {
		return
	}

	var users []models.User
	if err := s.db.Where("enabled = ?", true).Find(&users).Error; err != nil {
		logger.Error("Traffic sync: failed to fetch users: %v", err)
		return
	}

	updated := 0
	for _, user := range users {
		down, _ := client.GetStats("user>>>"+user.StatsKey()+">>>traffic>>>downlink", true)
		up, _ := client.GetStats("user>>>"+user.StatsKey()+">>>traffic>>>uplink", true)
		total := down + up
		if total <= 0 {
			continue
		}
		if err := s.db.Model(&models.User{}).
			Where("id = ?", user.ID).
			Update("traffic_used", gorm.Expr("traffic_used + ?", total)).Error; err != nil {
			logger.Error("Traffic sync: failed to update user %s: %v", user.StatsKey(), err)
			continue
		}
		updated++
	}

	if updated > 0 {
		logger.Debug("Traffic sync: updated %d users", updated)
	}
}

func (s *Server) startMonthlyTrafficReset() {
	go func() {
		s.runMonthlyResetIfNeeded()

		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.runMonthlyResetIfNeeded()
			}
		}
	}()
}

func (s *Server) runMonthlyResetIfNeeded() {
	now := time.Now()
	currentMonth := now.Format("2006-01")

	var stored models.Setting
	if err := s.db.First(&stored, "key = ?", "monthly_net_baseline_month").Error; err != nil {
		s.snapshotNetBaseline(currentMonth)
		return
	}

	if stored.Value == currentMonth {
		return
	}

	logger.Info("Monthly reset: new month %s (was %s), resetting traffic", currentMonth, stored.Value)
	s.resetAllUserTraffic(now)
	s.snapshotNetBaseline(currentMonth)
}

func (s *Server) resetAllUserTraffic(now time.Time) {
	result := s.db.Model(&models.User{}).
		Where("1 = 1").
		Updates(map[string]interface{}{
			"traffic_used":  int64(0),
			"traffic_reset": now,
		})
	if result.Error != nil {
		logger.Error("Monthly reset: failed to reset user traffic: %v", result.Error)
		return
	}
	logger.Info("Monthly reset: reset traffic for %d users", result.RowsAffected)
}

func (s *Server) snapshotNetBaseline(month string) {
	sysInfo, err := system.GetSystemInfo()
	if err != nil {
		logger.Error("Monthly reset: failed to read system info for baseline: %v", err)
		return
	}

	upsert := func(key, value string) {
		var setting models.Setting
		if err := s.db.Where("key = ?", key).First(&setting).Error; err == nil {
			setting.Value = value
			_ = s.db.Save(&setting).Error
		} else {
			_ = s.db.Create(&models.Setting{Key: key, Value: value}).Error
		}
	}

	upsert("monthly_net_baseline_sent", fmt.Sprintf("%d", sysInfo.NetBytesSent))
	upsert("monthly_net_baseline_recv", fmt.Sprintf("%d", sysInfo.NetBytesRecv))
	upsert("monthly_net_baseline_month", month)
}
