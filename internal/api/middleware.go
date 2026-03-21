package api

import (
	"net/http"

	"go.uber.org/zap"
)

// authMiddleware validates API key from request headers.
// Accepts X-TelemetryFlow-Key-ID or X-API-Key-ID headers.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health endpoint is always public
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Skip auth if no API key is configured (development mode)
		if s.config.APIKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check API key from headers
		apiKey := r.Header.Get("X-TelemetryFlow-Key-ID")
		if apiKey == "" {
			apiKey = r.Header.Get("X-API-Key-ID")
		}
		if apiKey == "" {
			apiKey = r.Header.Get("Authorization")
		}

		if apiKey != s.config.APIKey {
			s.logger.Debug("Agent API auth failed",
				zap.String("remote", r.RemoteAddr),
				zap.String("path", r.URL.Path),
			)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
