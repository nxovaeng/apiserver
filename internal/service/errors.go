package service

import (
	"errors"
	"net/http"
	"strings"

	"xray-panel-server/internal/dto"
)

// AppError represents a structured service-layer error mapped directly to OpenAPI ErrorResponse.
type AppError struct {
	HTTPStatus int
	Code       dto.ErrorCode
	Message    string
	Details    map[string]interface{}
	Cause      error
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Cause
}

func NewValidationError(msg string) *AppError {
	return &AppError{HTTPStatus: http.StatusBadRequest, Code: dto.ErrValidation, Message: msg}
}

func NewUnauthorizedError(msg string) *AppError {
	return &AppError{HTTPStatus: http.StatusUnauthorized, Code: dto.ErrUnauthorized, Message: msg}
}

func NewForbiddenError(msg string) *AppError {
	return &AppError{HTTPStatus: http.StatusForbidden, Code: dto.ErrForbidden, Message: msg}
}

func NewNotFoundError(msg string) *AppError {
	return &AppError{HTTPStatus: http.StatusNotFound, Code: dto.ErrNotFound, Message: msg}
}

func NewConflictError(msg string) *AppError {
	return &AppError{HTTPStatus: http.StatusConflict, Code: dto.ErrConflict, Message: msg}
}

func NewRateLimitedError(msg string) *AppError {
	return &AppError{HTTPStatus: http.StatusTooManyRequests, Code: dto.ErrRateLimited, Message: msg}
}

func NewXrayValidationError(msg string, details map[string]interface{}) *AppError {
	return &AppError{
		HTTPStatus: http.StatusBadRequest,
		Code:       dto.ErrXrayValidationFailed,
		Message:    msg,
		Details:    details,
	}
}

func NewSystemCommandError(msg string, cause error) *AppError {
	return &AppError{HTTPStatus: http.StatusInternalServerError, Code: dto.ErrSystemCommandFailed, Message: msg, Cause: cause}
}

func NewInternalError(msg string, cause error) *AppError {
	return &AppError{HTTPStatus: http.StatusInternalServerError, Code: dto.ErrInternal, Message: msg, Cause: cause}
}

// AsAppError extracts *AppError from err if present.
func AsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") || strings.Contains(msg, "duplicate")
}
