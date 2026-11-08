package server

import "net/http"

// anthropicWriter marks responses of the Anthropic Messages routes, so the
// router's own errors use Anthropic's shape:
// {"type": "error", "error": {"type": "not_found_error", "message": "..."}}.
// Upstream responses (errors included) are relayed unchanged.
type anthropicWriter struct{ http.ResponseWriter }

// Unwrap lets http.ResponseController reach the Flusher for streaming.
func (a *anthropicWriter) Unwrap() http.ResponseWriter { return a.ResponseWriter }

func anthropicErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&anthropicWriter{w}, r)
	})
}

func anthropicErrorType(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request_error"
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	case http.StatusServiceUnavailable, 529:
		return "overloaded_error"
	}
	return "api_error"
}
