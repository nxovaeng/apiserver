package service

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"xray-panel-server/internal/config"
	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
)

// AuthContext holds identity metadata for an authenticated Bearer token request.
type AuthContext struct {
	TokenID     string
	TokenName   string
	TokenPrefix string
	IsBootstrap bool
}

// TokenService manages revocable static Bearer API tokens and authentication.
type TokenService struct {
	db      *gorm.DB
	cfg     *config.Config
	version string
}

// NewTokenService constructs a TokenService.
func NewTokenService(db *gorm.DB, cfg *config.Config, version string) *TokenService {
	return &TokenService{db: db, cfg: cfg, version: version}
}

// Authenticate validates a raw Bearer token against bootstrap tokens (constant-time)
// and salted SHA-256 hashed tokens stored in SQLite.
//
// Bootstrap tokens are intentionally NOT salted or hashed: they live only in the
// server config file (never in the database) and are compared directly against
// the presented token in constant time. They are not listed by GET /tokens and
// cannot be revoked through the API; rotate them by editing the config file.
//
// Database tokens carry a per-token random salt, so they cannot be looked up by
// hash. All stored tokens are verified in turn (the table holds a handful of
// admin tokens). Rows with an empty Salt predate salting: they are verified once
// against the legacy unsalted hash and, on success, upgraded in place to a
// salted hash.
func (s *TokenService) Authenticate(rawToken, clientIP string) (*AuthContext, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, NewUnauthorizedError("Missing API token")
	}

	if s.cfg != nil {
		for idx, boot := range s.cfg.Auth.BootstrapTokens {
			boot = strings.TrimSpace(boot)
			if boot == "" {
				continue
			}
			if subtle.ConstantTimeCompare([]byte(rawToken), []byte(boot)) == 1 {
				return &AuthContext{
					TokenID:     fmt.Sprintf("bootstrap-%d", idx+1),
					TokenName:   fmt.Sprintf("bootstrap-%d", idx+1),
					TokenPrefix: models.TokenDisplayPrefix(boot),
					IsBootstrap: true,
				}, nil
			}
		}
	}

	var tokens []models.APIToken
	if err := s.db.Find(&tokens).Error; err != nil {
		return nil, NewUnauthorizedError("Invalid or revoked API token")
	}

	var matched *models.APIToken
	for i := range tokens {
		tok := &tokens[i]
		var want string
		var err error
		if tok.Salt != "" {
			want, err = models.HashAPITokenWithSalt(rawToken, tok.Salt)
			if err != nil {
				continue
			}
		} else {
			want = models.HashAPIToken(rawToken)
		}
		if len(want) == len(tok.TokenHash) && subtle.ConstantTimeCompare([]byte(want), []byte(tok.TokenHash)) == 1 {
			matched = tok
			break
		}
	}
	if matched == nil {
		return nil, NewUnauthorizedError("Invalid or revoked API token")
	}
	tok := matched

	now := time.Now()
	if !tok.IsValid(now) {
		return nil, NewUnauthorizedError("Invalid or revoked API token")
	}

	// One-time upgrade of a legacy unsalted row to a salted hash.
	updates := map[string]interface{}{
		"last_used_at": now,
		"last_ip":      clientIP,
	}
	if tok.Salt == "" {
		if salt, err := models.NewSalt(); err == nil {
			if hash, err := models.HashAPITokenWithSalt(rawToken, salt); err == nil {
				updates["salt"] = salt
				updates["token_hash"] = hash
			}
		}
	}
	_ = s.db.Model(&models.APIToken{}).Where("id = ?", tok.ID).Updates(updates).Error

	return &AuthContext{
		TokenID:     tok.ID,
		TokenName:   tok.Name,
		TokenPrefix: tok.TokenPrefix,
		IsBootstrap: false,
	}, nil
}

// Verify returns server metadata and current token details for GET /api/v1/auth/verify.
func (s *TokenService) Verify(ctx *AuthContext) *dto.AuthVerifyResponse {
	return &dto.AuthVerifyResponse{
		Valid:            true,
		TokenID:          ctx.TokenID,
		TokenName:        ctx.TokenName,
		TokenPrefix:      ctx.TokenPrefix,
		Version:          s.version,
		ServerPublicHost: models.GetServerPublicHost(s.db),
		SubDomain:        models.GetSubDomain(s.db),
		SubPath:          models.GetSubPath(s.db),
		PanelTitle:       models.GetSettingValue(s.db, "panel_title", "Xray Panel"),
	}
}

// List returns all API tokens without exposing hashes or plaintext secrets.
func (s *TokenService) List() (*dto.TokenListResponse, error) {
	var tokens []models.APIToken
	if err := s.db.Order("created_at DESC").Find(&tokens).Error; err != nil {
		return nil, NewInternalError("Failed to list API tokens", err)
	}

	dtos := make([]dto.APITokenDTO, len(tokens))
	for i, t := range tokens {
		dtos[i] = toTokenDTO(t)
	}
	return &dto.TokenListResponse{Tokens: dtos, Total: len(dtos)}, nil
}

// Create generates a new revocable static Bearer token and returns its plaintext once.
func (s *TokenService) Create(req dto.CreateTokenRequest) (*dto.CreateTokenResponse, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, NewValidationError("Token name is required")
	}
	if len(name) > 64 {
		return nil, NewValidationError("Token name must be <= 64 characters")
	}
	if req.ExpiresDays != nil && *req.ExpiresDays < 0 {
		return nil, NewValidationError("expires_days must be >= 0")
	}

	raw, prefix, hash, salt, err := models.GenerateAPIToken()
	if err != nil {
		return nil, NewInternalError("Failed to generate API token", err)
	}

	var expiresAt *time.Time
	if req.ExpiresDays != nil && *req.ExpiresDays > 0 {
		exp := time.Now().Add(time.Duration(*req.ExpiresDays) * 24 * time.Hour)
		expiresAt = &exp
	}

	tok := models.APIToken{
		Name:        name,
		TokenPrefix: prefix,
		TokenHash:   hash,
		Salt:        salt,
		ExpiresAt:   expiresAt,
	}
	if err := s.db.Create(&tok).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, NewConflictError("Token conflict, please retry")
		}
		return nil, NewInternalError("Failed to create API token", err)
	}

	return &dto.CreateTokenResponse{
		Token:          toTokenDTO(tok),
		PlaintextToken: raw,
	}, nil
}

// RevokeOrDelete marks a token as revoked, or permanently deletes it when purge is true.
func (s *TokenService) RevokeOrDelete(id string, purge bool) (*dto.TokenDeleteResponse, error) {
	var tok models.APIToken
	if err := s.db.First(&tok, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("API token not found")
	}

	if purge {
		if err := s.db.Delete(&models.APIToken{}, "id = ?", id).Error; err != nil {
			return nil, NewInternalError("Failed to delete API token", err)
		}
		return &dto.TokenDeleteResponse{ID: id, Revoked: true, Deleted: true}, nil
	}

	tok.Revoked = true
	if err := s.db.Save(&tok).Error; err != nil {
		return nil, NewInternalError("Failed to revoke API token", err)
	}
	return &dto.TokenDeleteResponse{ID: id, Revoked: true, Deleted: false}, nil
}

func toTokenDTO(t models.APIToken) dto.APITokenDTO {
	return dto.APITokenDTO{
		ID:          t.ID,
		Name:        t.Name,
		TokenPrefix: t.TokenPrefix,
		ExpiresAt:   t.ExpiresAt,
		Revoked:     t.Revoked,
		LastUsedAt:  t.LastUsedAt,
		LastIP:      t.LastIP,
		CreatedAt:   t.CreatedAt,
	}
}
