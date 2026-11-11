package dto

const AuthContextKey = "auth_context"

// ErrorCode defines standard API error codes aligned with api/openapi.yaml.
type ErrorCode string

const (
	ErrUnauthorized         ErrorCode = "UNAUTHORIZED"
	ErrRateLimited          ErrorCode = "RATE_LIMITED"
	ErrValidation           ErrorCode = "VALIDATION_ERROR"
	ErrNotFound             ErrorCode = "NOT_FOUND"
	ErrConflict             ErrorCode = "CONFLICT"
	ErrForbidden            ErrorCode = "FORBIDDEN"
	ErrXrayValidationFailed ErrorCode = "XRAY_VALIDATION_FAILED"
	ErrSystemCommandFailed  ErrorCode = "SYSTEM_COMMAND_FAILED"
	ErrInternal             ErrorCode = "INTERNAL_ERROR"
)

// ErrorDetail represents structured error information in error responses.
type ErrorDetail struct {
	Code    ErrorCode              `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// ErrorResponse is the standard envelope for failed API requests.
type ErrorResponse struct {
	Success bool        `json:"success"`
	Error   ErrorDetail `json:"error"`
}

// SuccessResponse is the standard envelope for successful API requests.
type SuccessResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
}

// Envelope is a typed JSON response envelope for client/test decoding.
type Envelope[T any] struct {
	Success bool         `json:"success"`
	Data    T            `json:"data"`
	Error   *ErrorDetail `json:"error,omitempty"`
}
