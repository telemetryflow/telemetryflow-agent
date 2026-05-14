// Package api provides HTTP middleware for the agent API.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
