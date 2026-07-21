// Package api exposes unexported symbols for external test packages.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// This file contains forwarding-only wrappers around unexported handlers,
// middleware, and struct fields so that external test packages (package
// api_test) can exercise them without accessing unexported symbols. It holds
// no production logic.
package api

import "net/http"

// HandleHealthExported wraps the unexported handleHealth handler.
func (s *Server) HandleHealthExported(w http.ResponseWriter, r *http.Request) {
	s.handleHealth(w, r)
}

// HandleCollectorsExported wraps the unexported handleCollectors handler.
func (s *Server) HandleCollectorsExported(w http.ResponseWriter, r *http.Request) {
	s.handleCollectors(w, r)
}

// HandleReloadExported wraps the unexported handleReload handler.
func (s *Server) HandleReloadExported(w http.ResponseWriter, r *http.Request) {
	s.handleReload(w, r)
}

// HandlePodLogsExported wraps the unexported handlePodLogs handler.
func (s *Server) HandlePodLogsExported(w http.ResponseWriter, r *http.Request) {
	s.handlePodLogs(w, r)
}

// AuthMiddlewareExported wraps the unexported authMiddleware.
func (s *Server) AuthMiddlewareExported(next http.Handler) http.Handler {
	return s.authMiddleware(next)
}

// AgentExported exposes the unexported agent field for test assertions.
func (s *Server) AgentExported() AgentProvider {
	return s.agent
}
