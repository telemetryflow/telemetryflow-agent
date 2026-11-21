package rum

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestProxy(t *testing.T, upstream string, origins []string) *Proxy {
	t.Helper()
	p, err := NewProxy(upstream, origins, 5*time.Second, nil)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	return p
}

func TestNewProxy_Validation(t *testing.T) {
	t.Parallel()
	if _, err := NewProxy("", []string{"*"}, 0, nil); err == nil {
		t.Fatal("expected error for empty upstream")
	}
	if _, err := NewProxy("not-a-url", []string{"*"}, 0, nil); err == nil {
		t.Fatal("expected error for invalid upstream")
	}
	if _, err := NewProxy("https://ingest.example", []string{"*"}, 0, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProxy_ForwardsBeacon(t *testing.T) {
	t.Parallel()
	var gotPath, gotKey, gotOrigin, gotBody, gotCT string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("X-TFO-RUM-Key")
		gotOrigin = r.Header.Get("Origin")
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("X-RateLimit-Remaining", "99")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream.URL, []string{"https://app.example"})
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+tracesPath, strings.NewReader(`{"resourceSpans":[]}`))
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TFO-RUM-Key", "rum_pub_abc123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if gotPath != tracesPath {
		t.Fatalf("upstream path = %q", gotPath)
	}
	if gotKey != "rum_pub_abc123" {
		t.Fatalf("public key not forwarded: %q", gotKey)
	}
	if gotOrigin != "https://app.example" {
		t.Fatalf("origin not forwarded: %q", gotOrigin)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type not forwarded: %q", gotCT)
	}
	if gotBody != `{"resourceSpans":[]}` {
		t.Fatalf("body not forwarded: %q", gotBody)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("upstream body not relayed: %q", string(body))
	}
	if resp.Header.Get("X-RateLimit-Remaining") != "99" {
		t.Fatalf("upstream header not relayed")
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("CORS origin missing: %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

func TestProxy_OriginNotAllowed(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be called for a rejected origin")
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream.URL, []string{"https://app.example"})
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+metricsPath, strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://evil.example")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxy_CORSPreflight(t *testing.T) {
	t.Parallel()
	p := newTestProxy(t, "https://ingest.example", []string{"https://app.example"})
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodOptions, srv.URL+tracesPath, nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Headers", "content-type,x-tfo-rum-key")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("preflight CORS origin missing")
	}
	if !strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "x-tfo-rum-key") {
		t.Fatalf("preflight did not echo requested headers")
	}
}

func TestProxy_AllowAllOrigins(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream.URL, []string{"*"})
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+tracesPath, strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://anything.example")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with allow-all, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("allow-all CORS origin = %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}
}

func TestProxy_UpstreamDown(t *testing.T) {
	t.Parallel()
	// Unreachable upstream (reserved TEST-NET address, instant failure via timeout).
	p, _ := NewProxy("http://127.0.0.1:0", []string{"*"}, 1*time.Second, nil)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+tracesPath, strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://app.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 on upstream failure, got %d", resp.StatusCode)
	}
}
