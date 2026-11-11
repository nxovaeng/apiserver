package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/service"
)

// SlidingWindowLimiter tracks timestamped events per IP over a sliding time window.
type SlidingWindowLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewSlidingWindowLimiter creates a sliding-window per-IP rate limiter.
func NewSlidingWindowLimiter(limit int, window time.Duration) *SlidingWindowLimiter {
	if limit <= 0 {
		limit = 15
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &SlidingWindowLimiter{
		attempts: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks whether the IP is currently below the limit without recording an event.
func (l *SlidingWindowLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(ip, time.Now())
	return len(l.attempts[ip]) < l.limit
}

// RecordAndAllow records an attempt for the IP and reports whether it was within limit.
func (l *SlidingWindowLimiter) RecordAndAllow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.pruneLocked(ip, now)
	if len(l.attempts[ip]) >= l.limit {
		return false
	}
	l.attempts[ip] = append(l.attempts[ip], now)
	return true
}

// RecordFailure appends a failed authentication attempt timestamp for ip.
func (l *SlidingWindowLimiter) RecordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.pruneLocked(ip, now)
	l.attempts[ip] = append(l.attempts[ip], now)
}

func (l *SlidingWindowLimiter) pruneLocked(ip string, now time.Time) {
	list := l.attempts[ip]
	if len(list) == 0 {
		return
	}
	valid := list[:0]
	for _, t := range list {
		if now.Sub(t) < l.window {
			valid = append(valid, t)
		}
	}
	if len(valid) == 0 {
		delete(l.attempts, ip)
	} else {
		l.attempts[ip] = valid
	}
}

// BearerAuthMiddleware enforces static Bearer token authentication with failure rate-limiting.
// Tokens are extracted strictly from `Authorization: Bearer <token>` and rejected if passed via URL query.
func BearerAuthMiddleware(tokenSvc *service.TokenService, failLimiter *SlidingWindowLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		if failLimiter != nil && !failLimiter.Allow(ip) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, dto.ErrorResponse{
				Success: false,
				Error: dto.ErrorDetail{
					Code:    dto.ErrRateLimited,
					Message: "Too many failed authentication attempts, please retry later",
				},
			})
			return
		}

		// Explicitly forbid passing tokens in URL query parameters to avoid server/proxy access log leaks.
		if c.Query("token") != "" || c.Query("api_key") != "" || c.Query("access_token") != "" {
			if failLimiter != nil {
				failLimiter.RecordFailure(ip)
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, dto.ErrorResponse{
				Success: false,
				Error: dto.ErrorDetail{
					Code:    dto.ErrUnauthorized,
					Message: "API tokens must be passed via Authorization header, not URL query parameters",
				},
			})
			return
		}

		authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
		if authHeader == "" {
			if failLimiter != nil {
				failLimiter.RecordFailure(ip)
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, dto.ErrorResponse{
				Success: false,
				Error: dto.ErrorDetail{
					Code:    dto.ErrUnauthorized,
					Message: "Missing Authorization Bearer token",
				},
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
			if failLimiter != nil {
				failLimiter.RecordFailure(ip)
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, dto.ErrorResponse{
				Success: false,
				Error: dto.ErrorDetail{
					Code:    dto.ErrUnauthorized,
					Message: "Invalid Authorization header format",
				},
			})
			return
		}

		authCtx, err := tokenSvc.Authenticate(parts[1], ip)
		if err != nil {
			if failLimiter != nil {
				failLimiter.RecordFailure(ip)
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, dto.ErrorResponse{
				Success: false,
				Error: dto.ErrorDetail{
					Code:    dto.ErrUnauthorized,
					Message: "Invalid or revoked API token",
				},
			})
			return
		}

		c.Set(dto.AuthContextKey, authCtx)
		c.Next()
	}
}
