package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"xray-panel-server/internal/dto"
	"xray-panel-server/internal/models"
)

// UserService handles proxy user management and subscription URL construction.
type UserService struct {
	db *gorm.DB
}

func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db}
}

func (s *UserService) List(query string) (*dto.UserListResponse, error) {
	var users []models.User
	tx := s.db.Order("created_at DESC")
	q := strings.TrimSpace(query)
	if q != "" {
		like := "%" + q + "%"
		tx = tx.Where("name LIKE ? OR email LIKE ?", like, like)
	}
	if err := tx.Find(&users).Error; err != nil {
		return nil, NewInternalError("Failed to list users", err)
	}

	subPrefix := models.GetSubPath(s.db)
	subDomain := models.GetSubDomain(s.db)
	publicHost := models.GetServerPublicHost(s.db)

	dtos := make([]dto.UserDTO, len(users))
	for i, u := range users {
		dtos[i] = toUserDTO(u, subPrefix, subDomain, publicHost)
	}

	return &dto.UserListResponse{Users: dtos, Total: len(dtos)}, nil
}

func (s *UserService) Get(id string) (*dto.UserDTO, error) {
	var user models.User
	if err := s.db.First(&user, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("User not found")
	}
	dto := s.toDTO(user)
	return &dto, nil
}

func (s *UserService) Create(req dto.CreateUserRequest) (*dto.UserDTO, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, NewValidationError("用户名不能为空")
	}
	if req.TrafficLimitBytes < 0 {
		return nil, NewValidationError("traffic_limit_bytes must be >= 0")
	}

	userUUID := strings.TrimSpace(req.UUID)
	if userUUID == "" {
		userUUID = uuid.New().String()
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	var expiryDate *time.Time
	if req.ExpiryDate != nil && !req.ExpiryDate.IsZero() {
		t := req.ExpiryDate.UTC()
		expiryDate = &t
	} else if req.ExpireDays != nil && *req.ExpireDays > 0 {
		t := time.Now().UTC().Add(time.Duration(*req.ExpireDays) * 24 * time.Hour)
		expiryDate = &t
	}

	user := models.User{
		UUID:         userUUID,
		Name:         name,
		Email:        strings.TrimSpace(req.Email),
		TrafficLimit: req.TrafficLimitBytes,
		TrafficUsed:  0,
		ExpiryDate:   expiryDate,
		Enabled:      enabled,
		Note:         strings.TrimSpace(req.Note),
		WGPubKey:     strings.TrimSpace(req.WGPubKey),
	}

	if err := s.db.Create(&user).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, NewConflictError("UUID or subscription path already exists")
		}
		return nil, NewInternalError("Failed to create user", err)
	}

	dto := s.toDTO(user)
	return &dto, nil
}

func (s *UserService) Update(id string, req dto.UpdateUserRequest) (*dto.UserDTO, error) {
	var existing models.User
	if err := s.db.First(&existing, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("User not found")
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, NewValidationError("用户名不能为空")
	}
	if req.TrafficLimitBytes < 0 {
		return nil, NewValidationError("traffic_limit_bytes must be >= 0")
	}

	existing.Name = name
	existing.Email = strings.TrimSpace(req.Email)
	if u := strings.TrimSpace(req.UUID); u != "" {
		existing.UUID = u
	}
	existing.TrafficLimit = req.TrafficLimitBytes
	if req.ExpiryDate != nil && !req.ExpiryDate.IsZero() {
		t := req.ExpiryDate.UTC()
		existing.ExpiryDate = &t
	} else {
		existing.ExpiryDate = nil
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	existing.Note = strings.TrimSpace(req.Note)
	existing.WGPubKey = strings.TrimSpace(req.WGPubKey)

	// Note: SubPath, TrafficUsed, TrafficReset, CreatedAt are intentionally preserved.
	if err := s.db.Save(&existing).Error; err != nil {
		if isUniqueConstraintErr(err) {
			return nil, NewConflictError("UUID already in use by another user")
		}
		return nil, NewInternalError("Failed to update user", err)
	}

	dto := s.toDTO(existing)
	return &dto, nil
}

func (s *UserService) Delete(id string) (*dto.DeleteResponse, error) {
	result := s.db.Delete(&models.User{}, "id = ?", id)
	if result.Error != nil {
		return nil, NewInternalError("Failed to delete user", result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, NewNotFoundError("User not found")
	}
	return &dto.DeleteResponse{ID: id, Deleted: true}, nil
}

func (s *UserService) Toggle(id string) (*dto.UserDTO, error) {
	var user models.User
	if err := s.db.First(&user, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("User not found")
	}
	user.Enabled = !user.Enabled
	if err := s.db.Save(&user).Error; err != nil {
		return nil, NewInternalError("Failed to toggle user", err)
	}
	dto := s.toDTO(user)
	return &dto, nil
}

func (s *UserService) ResetTraffic(id string) (*dto.UserDTO, error) {
	var user models.User
	if err := s.db.First(&user, "id = ?", id).Error; err != nil {
		return nil, NewNotFoundError("User not found")
	}
	now := time.Now().UTC()
	user.TrafficUsed = 0
	user.TrafficReset = &now
	if err := s.db.Save(&user).Error; err != nil {
		return nil, NewInternalError("Failed to reset user traffic", err)
	}
	dto := s.toDTO(user)
	return &dto, nil
}

func (s *UserService) toDTO(u models.User) dto.UserDTO {
	return toUserDTO(u, models.GetSubPath(s.db), models.GetSubDomain(s.db), models.GetServerPublicHost(s.db))
}

func toUserDTO(u models.User, subPrefix, subDomain, publicHost string) dto.UserDTO {
	rel := fmt.Sprintf("%s/%s", subPrefix, u.SubPath)
	baseHost := strings.TrimSpace(subDomain)
	if baseHost == "" {
		baseHost = strings.TrimSpace(publicHost)
	}
	baseHost = cleanHost(baseHost)

	base := rel
	if baseHost != "" {
		base = "https://" + baseHost + rel
	}

	return dto.UserDTO{
		ID:                    u.ID,
		UUID:                  u.UUID,
		Name:                  u.Name,
		Email:                 u.Email,
		TrafficLimitBytes:     u.TrafficLimit,
		TrafficUsedBytes:      u.TrafficUsed,
		RemainingTrafficBytes: u.RemainingTraffic(),
		TrafficResetAt:        u.TrafficReset,
		ExpiryDate:            u.ExpiryDate,
		RemainingDays:         u.RemainingDays(),
		Enabled:               u.Enabled,
		IsActive:              u.IsActive(),
		SubPath:               u.SubPath,
		SubURLs: dto.UserSubURLs{
			Base64:       base,
			Plain:        base + "/txt",
			JSON:         base + "/json",
			YAML:         base + "/yaml",
			RelativePath: rel,
		},
		Note:      u.Note,
		WGPubKey:  u.WGPubKey,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}
