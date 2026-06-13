package fsm

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

func supervisorCfg() *config.SupervisorConfig {
	return &config.SupervisorConfig{
		Enabled:   true,
		HotReload: true,
		FSM: config.CollectorFSMConfig{
			MaxStartRetries:       3,
			BackoffInitial:        10 * time.Millisecond,
			BackoffMax:            100 * time.Millisecond,
			BackoffMultiplier:     2.0,
			RestartOnConfigChange: true,
		},
	}
}

type mockMgrCollector struct {
	name     string
	running  atomic.Bool
	startErr error
	stopErr  error
}

func (m *mockMgrCollector) Name() string                                          { return m.name }
func (m *mockMgrCollector) Start(_ context.Context) error                         { m.running.Store(true); return m.startErr }
func (m *mockMgrCollector) Stop() error                                           { m.running.Store(false); return m.stopErr }
func (m *mockMgrCollector) Collect(_ context.Context) ([]collector.Metric, error) { return nil, nil }
func (m *mockMgrCollector) IsRunning() bool                                       { return m.running.Load() }

// ---------------------------------------------------------------------------
// Register + Start
// ---------------------------------------------------------------------------

func TestManager_RegisterAndStart(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "sys"}
	mgr.Register("sys", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	states := mgr.CollectorStates()
	if len(states) != 1 {
		t.Fatalf("expected 1 collector, got %d", len(states))
	}
	if states[0].State != collector.StateRunning {
		t.Fatalf("expected Running, got %s", states[0].State)
	}
}

// ---------------------------------------------------------------------------
// IsRunning
// ---------------------------------------------------------------------------

func TestManager_IsRunning_BeforeStart(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)
	if mgr.IsRunning() {
		t.Fatal("expected IsRunning=false before start")
	}
}

func TestManager_IsRunning_AfterStart(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "sys"}
	mgr.Register("sys", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)

	if !mgr.IsRunning() {
		t.Fatal("expected IsRunning=true after start")
	}
}

func TestManager_IsRunning_AfterStop(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "sys"}
	mgr.Register("sys", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	_ = mgr.Start(ctx)
	cancel()
	_ = mgr.Stop()

	if mgr.IsRunning() {
		t.Fatal("expected IsRunning=false after stop")
	}
}

// ---------------------------------------------------------------------------
// Double Start / Double Stop
// ---------------------------------------------------------------------------

func TestManager_DoubleStart(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "sys"}
	mgr.Register("sys", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = mgr.Start(ctx)
	err := mgr.Start(ctx)
	if err != nil {
		t.Fatalf("second start should be no-op, got: %v", err)
	}
}

func TestManager_DoubleStop(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	ctx, cancel := context.WithCancel(context.Background())
	_ = mgr.Start(ctx)
	cancel()
	_ = mgr.Stop()
	_ = mgr.Stop()
}

func TestManager_StopWithoutStart(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)
	_ = mgr.Stop()
}

// ---------------------------------------------------------------------------
// Stop with timeout
// ---------------------------------------------------------------------------

func TestManager_StopWaitsForCollectors(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "sys"}
	mgr.Register("sys", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	_ = mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()

	_ = mgr.Stop()

	states := mgr.CollectorStates()
	if states[0].State != collector.StateStopped {
		t.Fatalf("expected Stopped, got %s", states[0].State)
	}
}

// ---------------------------------------------------------------------------
// ApplyDiff — Add
// ---------------------------------------------------------------------------

func TestManager_ApplyDiff_Add(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc1 := &mockMgrCollector{name: "sys"}
	mgr.Register("sys", mc1, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	mc2 := &mockMgrCollector{name: "docker"}
	entries := []collector.CollectorEntry{
		{Name: "sys", Collector: mc1, ConfigHash: collector.DigestConfig("v1")},
		{Name: "docker", Collector: mc2, ConfigHash: collector.DigestConfig("v1")},
	}

	if err := mgr.ApplyDiff(entries); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	stats := mgr.Stats()
	if stats.Total != 2 {
		t.Fatalf("expected 2 total, got %d", stats.Total)
	}
	if stats.Running != 2 {
		t.Fatalf("expected 2 running, got %d", stats.Running)
	}
}

// ---------------------------------------------------------------------------
// ApplyDiff — Remove
// ---------------------------------------------------------------------------

func TestManager_ApplyDiff_Remove(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc1 := &mockMgrCollector{name: "sys"}
	mc2 := &mockMgrCollector{name: "docker"}
	mgr.Register("sys", mc1, collector.DigestConfig("v1"))
	mgr.Register("docker", mc2, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	entries := []collector.CollectorEntry{
		{Name: "sys", Collector: mc1, ConfigHash: collector.DigestConfig("v1")},
	}

	if err := mgr.ApplyDiff(entries); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	stats := mgr.Stats()
	if stats.Total != 1 {
		t.Fatalf("expected 1 total, got %d", stats.Total)
	}
}

// ---------------------------------------------------------------------------
// ApplyDiff — Restart (config change)
// ---------------------------------------------------------------------------

func TestManager_ApplyDiff_Restart(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "sys"}
	mgr.Register("sys", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	oldStates := mgr.CollectorStates()
	if oldStates[0].State != collector.StateRunning {
		t.Fatalf("expected Running before diff, got %s", oldStates[0].State)
	}

	entries := []collector.CollectorEntry{
		{Name: "sys", Collector: mc, ConfigHash: collector.DigestConfig("v2")},
	}

	if err := mgr.ApplyDiff(entries); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	newStates := mgr.CollectorStates()
	if newStates[0].State != collector.StateRunning {
		t.Fatalf("expected Running after restart, got %s", newStates[0].State)
	}
}

// ---------------------------------------------------------------------------
// ApplyDiff — Remove nonexistent (no-op)
// ---------------------------------------------------------------------------

func TestManager_ApplyDiff_RemoveNonexistent(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "sys"}
	mgr.Register("sys", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	entries := []collector.CollectorEntry{
		{Name: "sys", Collector: mc, ConfigHash: collector.DigestConfig("v1")},
	}

	_ = mgr.ApplyDiff(entries)
	stats := mgr.Stats()
	if stats.Total != 1 {
		t.Fatalf("expected 1 total, got %d", stats.Total)
	}
}

// ---------------------------------------------------------------------------
// ApplyDiff — Add already existing (no-op)
// ---------------------------------------------------------------------------

func TestManager_ApplyDiff_AddExisting(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "sys"}
	h := collector.DigestConfig("v1")
	mgr.Register("sys", mc, h)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	entries := []collector.CollectorEntry{
		{Name: "sys", Collector: mc, ConfigHash: h},
	}

	_ = mgr.ApplyDiff(entries)
	stats := mgr.Stats()
	if stats.Total != 1 {
		t.Fatalf("expected 1 total, got %d", stats.Total)
	}
}

// ---------------------------------------------------------------------------
// Stats — all state categories
// ---------------------------------------------------------------------------

func TestManager_Stats_AllStates(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mcOK := &mockMgrCollector{name: "ok"}
	mcFail := &mockMgrCollector{name: "fail", startErr: errors.New("nope")}
	mgr.Register("ok", mcOK, collector.DigestConfig("v1"))
	mgr.Register("fail", mcFail, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	stats := mgr.Stats()
	if stats.Total != 2 {
		t.Fatalf("expected 2 total, got %d", stats.Total)
	}
	if stats.Running < 1 {
		t.Fatalf("expected at least 1 running, got %d", stats.Running)
	}
}

func TestManager_Stats_Empty(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)
	stats := mgr.Stats()
	if stats.Total != 0 {
		t.Fatalf("expected 0 total, got %d", stats.Total)
	}
}

func TestManager_Stats_StoppedCollector(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "stopme"}
	mgr.Register("stopme", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	_ = mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	_ = mgr.Stop()

	stats := mgr.Stats()
	if stats.Stopped < 1 {
		t.Fatalf("expected at least 1 stopped, got %d (total=%d)", stats.Stopped, stats.Total)
	}
}

// ---------------------------------------------------------------------------
// FormatStats
// ---------------------------------------------------------------------------

func TestManager_FormatStats(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "sys"}
	mgr.Register("sys", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	s := mgr.FormatStats()
	if s == "" {
		t.Fatal("expected non-empty stats string")
	}
}

func TestManager_FormatStats_Empty(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)
	s := mgr.FormatStats()
	if s == "" {
		t.Fatal("expected non-empty stats even when empty")
	}
}

// ---------------------------------------------------------------------------
// CollectorStates
// ---------------------------------------------------------------------------

func TestManager_CollectorStates_Empty(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)
	states := mgr.CollectorStates()
	if len(states) != 0 {
		t.Fatalf("expected 0 states, got %d", len(states))
	}
}

// ---------------------------------------------------------------------------
// Failed collector (retry loop)
// ---------------------------------------------------------------------------

func TestManager_FailedCollector(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "fail", startErr: context.DeadlineExceeded}
	mgr.Register("fail", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)

	time.Sleep(100 * time.Millisecond)

	states := mgr.CollectorStates()
	found := false
	for _, s := range states {
		if s.Name == "fail" && (s.State == collector.StateFailed || s.State == collector.StateBackoff) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Failed or Backoff state, got %v", states)
	}
}

// ---------------------------------------------------------------------------
// Retry loop revives collector
// ---------------------------------------------------------------------------

func TestManager_RetryRevive(t *testing.T) {
	logger := zap.NewNop()
	cfg := supervisorCfg()
	cfg.FSM.BackoffInitial = 5 * time.Millisecond
	cfg.FSM.BackoffMax = 10 * time.Millisecond

	mgr := collector.NewManager(cfg, logger)

	var attempts atomic.Int32
	mc := &retryReviveCollector{name: "revive", failUntil: 2, attempts: &attempts}
	mgr.Register("revive", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)

	deadline := time.After(12 * time.Second)
	for {
		select {
		case <-deadline:
			states := mgr.CollectorStates()
			t.Fatalf("expected Running after revive, got %v", states)
		default:
		}
		states := mgr.CollectorStates()
		for _, s := range states {
			if s.Name == "revive" && s.State == collector.StateRunning {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}

type retryReviveCollector struct {
	name      string
	failUntil int32
	attempts  *atomic.Int32
	running   atomic.Bool
}

func (r *retryReviveCollector) Name() string { return r.name }
func (r *retryReviveCollector) Stop() error  { r.running.Store(false); return nil }
func (r *retryReviveCollector) Collect(_ context.Context) ([]collector.Metric, error) {
	return nil, nil
}
func (r *retryReviveCollector) IsRunning() bool { return r.running.Load() }
func (r *retryReviveCollector) Start(_ context.Context) error {
	n := r.attempts.Add(1)
	if n <= r.failUntil {
		return errors.New("temp fail")
	}
	r.running.Store(true)
	return nil
}

// ---------------------------------------------------------------------------
// Stop with collector stop error
// ---------------------------------------------------------------------------

func TestManager_StopWithCollectorError(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	mc := &mockMgrCollector{name: "stoperr", stopErr: errors.New("stop boom")}
	mgr.Register("stoperr", mc, collector.DigestConfig("v1"))

	ctx, cancel := context.WithCancel(context.Background())
	_ = mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()

	_ = mgr.Stop()

	states := mgr.CollectorStates()
	if len(states) == 0 {
		t.Fatal("expected at least 1 collector state")
	}
	if states[0].State != collector.StateFailed {
		t.Fatalf("expected Failed (stop error), got %s", states[0].State)
	}
}

// ---------------------------------------------------------------------------
// Register after start (should register but not auto-start)
// ---------------------------------------------------------------------------

func TestManager_RegisterAfterStart(t *testing.T) {
	logger := zap.NewNop()
	mgr := collector.NewManager(supervisorCfg(), logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = mgr.Start(ctx)

	mc := &mockMgrCollector{name: "late"}
	mgr.Register("late", mc, collector.DigestConfig("v1"))

	time.Sleep(50 * time.Millisecond)

	// Collector is registered but not started (Start was already called)
	states := mgr.CollectorStates()
	if len(states) != 1 {
		t.Fatalf("expected 1 collector, got %d", len(states))
	}
	if states[0].State != collector.StateNew {
		t.Fatalf("expected New (not started by Start()), got %s", states[0].State)
	}
}
