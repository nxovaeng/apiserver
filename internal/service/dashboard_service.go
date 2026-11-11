package service

import (
	"strconv"
	"time"

	"gorm.io/gorm"

	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
	"xray-panel-server/internal/system"
	"xray-panel-server/internal/wireguard"
)

// DashboardService aggregates node counts, system metrics, monthly traffic, and service status.
type DashboardService struct {
	db     *gorm.DB
	sysSvc *SystemService
	wgMgr  *wireguard.Manager
}

func NewDashboardService(db *gorm.DB, sysSvc *SystemService) *DashboardService {
	return &DashboardService{
		db:     db,
		sysSvc: sysSvc,
		wgMgr:  wireguard.NewManager(db),
	}
}

func (s *DashboardService) GetDashboard() (*dto.DashboardResponse, error) {
	var usersTotal, usersActive int64
	var inbTotal, inbActive int64
	var outTotal, outActive int64
	var domTotal, domActive int64
	var ruleTotal, ruleActive int64
	var usersTraffic int64

	s.db.Model(&models.User{}).Count(&usersTotal)
	s.db.Model(&models.User{}).Where("enabled = ?", true).Count(&usersActive)
	s.db.Model(&models.Inbound{}).Count(&inbTotal)
	s.db.Model(&models.Inbound{}).Where("enabled = ?", true).Count(&inbActive)
	s.db.Model(&models.Outbound{}).Count(&outTotal)
	s.db.Model(&models.Outbound{}).Where("enabled = ?", true).Count(&outActive)
	s.db.Model(&models.Domain{}).Count(&domTotal)
	s.db.Model(&models.Domain{}).Where("enabled = ?", true).Count(&domActive)
	s.db.Model(&models.RoutingRule{}).Count(&ruleTotal)
	s.db.Model(&models.RoutingRule{}).Where("enabled = ?", true).Count(&ruleActive)
	s.db.Model(&models.User{}).Select("COALESCE(SUM(traffic_used), 0)").Scan(&usersTraffic)

	sysInfo, err := system.GetSystemInfo()
	if err != nil || sysInfo == nil {
		sysInfo = &system.SystemInfo{}
	}

	netSent := sysInfo.NetBytesSent
	netRecv := sysInfo.NetBytesRecv
	currentMonth := time.Now().Format("2006-01")
	baselineMonth := models.GetSettingValue(s.db, "monthly_net_baseline_month", "")

	if baselineMonth == currentMonth {
		if v, err := strconv.ParseUint(models.GetSettingValue(s.db, "monthly_net_baseline_sent", ""), 10, 64); err == nil && netSent >= v {
			netSent -= v
		}
		if v, err := strconv.ParseUint(models.GetSettingValue(s.db, "monthly_net_baseline_recv", ""), 10, 64); err == nil && netRecv >= v {
			netRecv -= v
		}
	}

	xrayStatus := s.sysSvc.GetXrayStatus()
	wgStatus, wgErr := s.wgMgr.GetStatus()
	if wgErr != nil || wgStatus == nil {
		wgStatus = &wireguard.ServiceStatus{InterfaceName: "wg0"}
	}

	return &dto.DashboardResponse{
		Users:        dto.DashboardCounts{Total: usersTotal, Active: usersActive},
		Inbounds:     dto.DashboardCounts{Total: inbTotal, Active: inbActive},
		Outbounds:    dto.DashboardCounts{Total: outTotal, Active: outActive},
		Domains:      dto.DashboardCounts{Total: domTotal, Active: domActive},
		RoutingRules: dto.DashboardCounts{Total: ruleTotal, Active: ruleActive},
		Traffic: dto.DashboardTraffic{
			UsersTrafficUsedBytes: usersTraffic,
			MonthlyNetSentBytes:   netSent,
			MonthlyNetRecvBytes:   netRecv,
			MonthlyNetTotalBytes:  netSent + netRecv,
			BaselineMonth:         baselineMonth,
		},
		System: dto.DashboardSystemMetrics{
			Hostname:        sysInfo.Hostname,
			OS:              sysInfo.OS,
			Platform:        sysInfo.Platform,
			UptimeSeconds:   uint64(sysInfo.Uptime.Seconds()),
			GoVersion:       sysInfo.GoVersion,
			CPUModel:        sysInfo.CPUModel,
			CPUCores:        sysInfo.CPUCores,
			CPUUsagePercent: sysInfo.CPUUsage,
			MemTotalBytes:   sysInfo.MemTotal,
			MemUsedBytes:    sysInfo.MemUsed,
			MemFreeBytes:    sysInfo.MemFree,
			MemPercent:      sysInfo.MemPercent,
			DiskTotalBytes:  sysInfo.DiskTotal,
			DiskUsedBytes:   sysInfo.DiskUsed,
			DiskFreeBytes:   sysInfo.DiskFree,
			DiskPercent:     sysInfo.DiskPercent,
		},
		Services: dto.DashboardServices{
			XrayActive:           xrayStatus.Active,
			XrayStatus:           xrayStatus.Status,
			WireguardInstalled:   wgStatus.IsInstalled,
			WireguardActive:      wgStatus.IsActive,
			WireguardInterface:   wgStatus.InterfaceName,
			WireguardOnlinePeers: wgStatus.OnlinePeers,
			WireguardTotalPeers:  wgStatus.TotalPeers,
		},
	}, nil
}
