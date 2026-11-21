package deploy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     Request
		wantErr bool
	}{
		{"ok minimal", Request{Service: "checkout", Version: "2.6.0"}, false},
		{"ok full", Request{Service: "s", Version: "v", Provider: "github", Status: "success"}, false},
		{"missing service", Request{Version: "2.6.0"}, true},
		{"missing version", Request{Service: "checkout"}, true},
		{"bad status", Request{Service: "s", Version: "v", Status: "done"}, true},
		{"bad provider", Request{Service: "s", Version: "v", Provider: "heroku"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestReporter_Report_Success(t *testing.T) {
	t.Parallel()
	var gotKeyID, gotKeySecret, gotCT string
	var gotBody Request

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != deploymentsPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotKeyID = r.Header.Get(keyIDHeaderName)
		gotKeySecret = r.Header.Get(keySecretHdrName)
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"deployment_id":"dep-1","created":true,"status":"success","status_changed":true}}`))
	}))
	defer srv.Close()

	r := NewReporter(srv.URL, "tfk_abc", "tfs_xyz", 5*time.Second)
	resp, err := r.Report(context.Background(), Request{
		Service: "checkout", Version: "2.6.0", Status: "success", Provider: "github",
	})
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	if resp.Data.DeploymentID != "dep-1" || !resp.Data.Created {
		t.Fatalf("unexpected response: %+v", resp.Data)
	}
	if gotKeyID != "tfk_abc" || gotKeySecret != "tfs_xyz" {
		t.Fatalf("auth headers not sent: id=%q secret=%q", gotKeyID, gotKeySecret)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type = %q", gotCT)
	}
	if gotBody.Service != "checkout" || gotBody.Version != "2.6.0" {
		t.Fatalf("payload mismatch: %+v", gotBody)
	}
}

func TestReporter_Report_ServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"invalid key"}`))
	}))
	defer srv.Close()

	r := NewReporter(srv.URL, "bad", "bad", 5*time.Second)
	_, err := r.Report(context.Background(), Request{Service: "s", Version: "v"})
	if err == nil {
		t.Fatal("expected error on 401, got nil")
	}
}

func TestReporter_Report_ValidationShortCircuits(t *testing.T) {
	t.Parallel()
	// No server: a validation failure must return before any HTTP call.
	r := NewReporter("http://127.0.0.1:0", "k", "s", time.Second)
	if _, err := r.Report(context.Background(), Request{Version: "v"}); err == nil {
		t.Fatal("expected validation error for missing service")
	}
}

func TestReporter_Report_EmptyEndpoint(t *testing.T) {
	t.Parallel()
	r := NewReporter("", "k", "s", time.Second)
	if _, err := r.Report(context.Background(), Request{Service: "s", Version: "v"}); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}
