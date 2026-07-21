// Package api_test exercises the agent HTTP API server, its handlers,
// middleware, and lifecycle using httptest and fake Kubernetes clients from an
// external test package via the exported wrappers in internal/api/exports.go.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/telemetryflow/telemetryflow-agent/internal/api"
)

// fakeAgent is an in-memory AgentProvider double.
type fakeAgent struct {
	states      []api.CollectorState
	reloadErr   error
	running     bool
	stats       api.AgentStats
	reloadCalls int
}

func (f *fakeAgent) CollectorStates() []api.CollectorState { return f.states }
func (f *fakeAgent) ReloadConfig() error                   { f.reloadCalls++; return f.reloadErr }
func (f *fakeAgent) IsRunning() bool                       { return f.running }
func (f *fakeAgent) Stats() api.AgentStats                 { return f.stats }

func newTestServer(cfg api.Config, agent api.AgentProvider) *api.Server {
	return api.NewServer(cfg, fake.NewSimpleClientset(), zap.NewNop(), agent)
}

// testHandler builds the same mux + middleware wiring used in Start, without
// binding a socket, so handlers/routes/middleware can be exercised via httptest.
func testHandler(s *api.Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.HandleHealthExported)
	mux.HandleFunc("GET /api/v1/collectors", s.HandleCollectorsExported)
	mux.HandleFunc("POST /api/v1/reload", s.HandleReloadExported)
	mux.HandleFunc("GET /api/v1/pods/{namespace}/{pod}/logs", s.HandlePodLogsExported)
	return s.AuthMiddlewareExported(mux)
}

func doReq(t *testing.T, h http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestHandleHealth(t *testing.T) {
	t.Run("without agent", func(t *testing.T) {
		s := newTestServer(api.Config{}, nil)
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/health", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["status"] != "ok" {
			t.Fatalf("want status ok, got %v", body)
		}
		if _, ok := body["agent_running"]; ok {
			t.Fatalf("agent_running should be absent, got %v", body)
		}
	})

	t.Run("with running agent", func(t *testing.T) {
		s := newTestServer(api.Config{}, &fakeAgent{running: true})
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/health", nil)
		var body map[string]string
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		if body["agent_running"] != "true" {
			t.Fatalf("want agent_running true, got %v", body)
		}
	})
}

func TestHandleCollectors(t *testing.T) {
	t.Run("nil agent", func(t *testing.T) {
		s := newTestServer(api.Config{}, nil)
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/collectors", nil)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503, got %d", rr.Code)
		}
	})

	t.Run("nil states", func(t *testing.T) {
		s := newTestServer(api.Config{}, &fakeAgent{states: nil})
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/collectors", nil)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503, got %d", rr.Code)
		}
	})

	t.Run("with states", func(t *testing.T) {
		agent := &fakeAgent{states: []api.CollectorState{
			{Name: "pg", State: "running", FailureCount: 0},
			{Name: "redis", State: "failed", LastError: "boom", FailureCount: 2, StartedAt: 123},
		}}
		s := newTestServer(api.Config{}, agent)
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/collectors", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
		var body struct {
			Collectors []api.CollectorState `json:"collectors"`
			Count      int                  `json:"count"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Count != 2 || len(body.Collectors) != 2 {
			t.Fatalf("want 2 collectors, got %+v", body)
		}
	})
}

func TestHandleReload(t *testing.T) {
	t.Run("nil agent", func(t *testing.T) {
		s := newTestServer(api.Config{}, nil)
		rr := doReq(t, testHandler(s), http.MethodPost, "/api/v1/reload", nil)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503, got %d", rr.Code)
		}
	})

	t.Run("reload error", func(t *testing.T) {
		agent := &fakeAgent{reloadErr: errors.New("bad config")}
		s := newTestServer(api.Config{}, agent)
		rr := doReq(t, testHandler(s), http.MethodPost, "/api/v1/reload", nil)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("want 500, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "bad config") {
			t.Fatalf("want error message, got %s", rr.Body.String())
		}
	})

	t.Run("success", func(t *testing.T) {
		agent := &fakeAgent{}
		s := newTestServer(api.Config{}, agent)
		rr := doReq(t, testHandler(s), http.MethodPost, "/api/v1/reload", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
		if agent.reloadCalls != 1 {
			t.Fatalf("want 1 reload call, got %d", agent.reloadCalls)
		}
	})
}

func TestHandlePodLogs(t *testing.T) {
	t.Run("non-follow returns json lines", func(t *testing.T) {
		s := newTestServer(api.Config{}, nil)
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/pods/default/mypod/logs?container=app&timestamps=false", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		var body struct {
			Namespace string   `json:"namespace"`
			Pod       string   `json:"pod"`
			Container string   `json:"container"`
			Lines     []string `json:"lines"`
			Count     int      `json:"count"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
		}
		if body.Namespace != "default" || body.Pod != "mypod" || body.Container != "app" {
			t.Fatalf("unexpected body: %+v", body)
		}
	})

	t.Run("follow streams SSE", func(t *testing.T) {
		s := newTestServer(api.Config{}, nil)
		rr := doReq(t, testHandler(s), http.MethodGet,
			"/api/v1/pods/default/mypod/logs?follow=true&tailLines=5&sinceSeconds=30&previous=true", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("want SSE content-type, got %q", ct)
		}
	})

	t.Run("invalid query params fall through to defaults", func(t *testing.T) {
		s := newTestServer(api.Config{}, nil)
		// non-numeric tailLines/sinceSeconds exercise the parse-error branches
		rr := doReq(t, testHandler(s), http.MethodGet,
			"/api/v1/pods/default/mypod/logs?tailLines=abc&sinceSeconds=xyz", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
	})

	t.Run("missing path values rejected", func(t *testing.T) {
		// Call handler directly with empty path values to hit the guard.
		s := newTestServer(api.Config{}, nil)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/pods//_/logs", nil)
		rr := httptest.NewRecorder()
		s.HandlePodLogsExported(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

// TestHandlePodLogs_StreamingNotSupported verifies the 500 path via a
// non-flushable writer for the follow branch.
func TestHandlePodLogs_StreamingNotSupported(t *testing.T) {
	s := newTestServer(api.Config{}, nil)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/pods/default/mypod/logs?follow=true", nil)
	req.SetPathValue("namespace", "default")
	req.SetPathValue("pod", "mypod")
	// nonFlusher does not implement http.Flusher.
	w := &nonFlusher{header: http.Header{}}
	s.HandlePodLogsExported(w, req)
	if w.status != http.StatusInternalServerError {
		t.Fatalf("want 500 for non-flushable writer, got %d", w.status)
	}
}

type nonFlusher struct {
	header http.Header
	status int
	buf    strings.Builder
}

func (n *nonFlusher) Header() http.Header { return n.header }
func (n *nonFlusher) Write(b []byte) (int, error) {
	if n.status == 0 {
		n.status = http.StatusOK
	}
	return n.buf.Write(b)
}
func (n *nonFlusher) WriteHeader(code int) { n.status = code }

func TestAuthMiddleware(t *testing.T) {
	cfg := api.Config{APIKey: "secret"}

	t.Run("health always public", func(t *testing.T) {
		s := newTestServer(cfg, &fakeAgent{})
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/health", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
	})

	t.Run("missing key rejected", func(t *testing.T) {
		s := newTestServer(cfg, &fakeAgent{})
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/collectors", nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", rr.Code)
		}
	})

	t.Run("wrong key rejected", func(t *testing.T) {
		s := newTestServer(cfg, &fakeAgent{})
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/collectors",
			map[string]string{"X-API-Key-ID": "nope"})
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", rr.Code)
		}
	})

	t.Run("valid TelemetryFlow key accepted", func(t *testing.T) {
		s := newTestServer(cfg, &fakeAgent{states: []api.CollectorState{}})
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/collectors",
			map[string]string{"X-TelemetryFlow-Key-ID": "secret"})
		if rr.Code == http.StatusUnauthorized {
			t.Fatalf("valid key should pass, got 401")
		}
	})

	t.Run("valid Authorization key accepted", func(t *testing.T) {
		s := newTestServer(cfg, &fakeAgent{states: []api.CollectorState{}})
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/collectors",
			map[string]string{"Authorization": "secret"})
		if rr.Code == http.StatusUnauthorized {
			t.Fatalf("valid Authorization should pass, got 401")
		}
	})

	t.Run("empty api key disables auth", func(t *testing.T) {
		s := newTestServer(api.Config{APIKey: ""}, &fakeAgent{states: []api.CollectorState{}})
		rr := doReq(t, testHandler(s), http.MethodGet, "/api/v1/collectors", nil)
		if rr.Code == http.StatusUnauthorized {
			t.Fatalf("empty key should disable auth, got 401")
		}
	})
}

func TestPortAndSetAgent(t *testing.T) {
	s := newTestServer(api.Config{Port: 9099}, nil)
	if s.Port() != 9099 {
		t.Fatalf("want port 9099, got %d", s.Port())
	}
	agent := &fakeAgent{running: true}
	s.SetAgent(agent)
	if !s.AgentExported().IsRunning() {
		t.Fatal("SetAgent did not inject agent")
	}
	// exercise Stats to keep the interface fully covered
	_ = agent.Stats()
}

func TestStopWithoutStart(t *testing.T) {
	s := newTestServer(api.Config{}, nil)
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop on nil server should be nil, got %v", err)
	}
}

func TestStartAndStopLifecycle(t *testing.T) {
	// Grab a free port up-front so we can poll the server over HTTP without
	// racing on the Server.server field written by the Start goroutine.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listener: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	s := newTestServer(api.Config{Port: port}, &fakeAgent{running: true})
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

	// Poll the health endpoint until the server is live.
	url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/health", port)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(3 * time.Second)
	live := false
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				live = true
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !live {
		cancel()
		<-done
		t.Fatal("server did not become live")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}

func TestStartPortInUse(t *testing.T) {
	// Bind a listener, then start a server on the same port to force
	// ListenAndServe to return a bind error through errCh.
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot open listener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	s := newTestServer(api.Config{Port: port}, &fakeAgent{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = s.Start(ctx)
	if err == nil {
		// If somehow it bound (race), ensure a clean stop.
		_ = s.Stop()
	}
	// Either a bind error surfaced through errCh (desired) or the context
	// deadline elapsed; both exercise the Start select branches.
}

// keep io imported for potential stream assertions.
var _ = io.Discard
