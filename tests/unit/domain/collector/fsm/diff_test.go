package fsm

import (
	"encoding/json"
	"testing"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

func makeTestFSMs(names ...string) map[string]*collector.CollectorFSM {
	logger := zap.NewNop()
	m := make(map[string]*collector.CollectorFSM, len(names))
	for _, n := range names {
		m[n] = collector.NewCollectorFSM(n, nil, collector.FSMConfig{}, logger)
	}
	return m
}

func assertDiffEmpty(t *testing.T, r collector.DiffResult) {
	t.Helper()
	if len(r.ToStart) != 0 || len(r.ToStop) != 0 || len(r.ToRestart) != 0 {
		t.Fatalf("expected empty diff, got start=%v stop=%v restart=%v",
			r.ToStart, r.ToStop, r.ToRestart)
	}
}

func TestComputeDiff_Empty(t *testing.T) {
	result := collector.ComputeDiff(nil, nil)
	assertDiffEmpty(t, result)
}

func TestComputeDiff_AllNew(t *testing.T) {
	entries := []collector.CollectorEntry{
		{Name: "system"},
		{Name: "docker"},
	}
	result := collector.ComputeDiff(nil, entries)
	if len(result.ToStart) != 2 {
		t.Fatalf("expected 2 toStart, got %d", len(result.ToStart))
	}
	if len(result.ToStop) != 0 {
		t.Fatalf("expected 0 toStop, got %d", len(result.ToStop))
	}
}

func TestComputeDiff_RemoveAll(t *testing.T) {
	fsms := makeTestFSMs("system")
	result := collector.ComputeDiff(fsms, nil)
	if len(result.ToStop) != 1 {
		t.Fatalf("expected 1 toStop, got %d", len(result.ToStop))
	}
	if result.ToStop[0] != "system" {
		t.Fatalf("expected 'system', got %s", result.ToStop[0])
	}
}

func TestComputeDiff_NoChange(t *testing.T) {
	hash := collector.DigestConfig("same")
	fsms := makeTestFSMs("system")
	fsms["system"].SetConfigHash(hash)

	entries := []collector.CollectorEntry{
		{Name: "system", ConfigHash: hash},
	}
	result := collector.ComputeDiff(fsms, entries)
	assertDiffEmpty(t, result)
}

func TestComputeDiff_ConfigChanged(t *testing.T) {
	oldHash := collector.DigestConfig("v1")
	newHash := collector.DigestConfig("v2")
	fsms := makeTestFSMs("system")
	fsms["system"].SetConfigHash(oldHash)

	entries := []collector.CollectorEntry{
		{Name: "system", ConfigHash: newHash},
	}
	result := collector.ComputeDiff(fsms, entries)
	if len(result.ToRestart) != 1 {
		t.Fatalf("expected 1 toRestart, got %d", len(result.ToRestart))
	}
	if result.ToRestart[0] != "system" {
		t.Fatalf("expected 'system', got %s", result.ToRestart[0])
	}
}

func TestComputeDiff_Mixed(t *testing.T) {
	h1 := collector.DigestConfig("a")
	h2 := collector.DigestConfig("b")
	hChanged := collector.DigestConfig("c")

	fsms := makeTestFSMs("system", "docker", "removed")
	fsms["system"].SetConfigHash(h1)
	fsms["docker"].SetConfigHash(h2)

	entries := []collector.CollectorEntry{
		{Name: "system", ConfigHash: h1},
		{Name: "docker", ConfigHash: hChanged},
		{Name: "new_collector"},
	}
	result := collector.ComputeDiff(fsms, entries)

	if len(result.ToStop) != 1 || result.ToStop[0] != "removed" {
		t.Fatalf("expected toStop=['removed'], got %v", result.ToStop)
	}
	if len(result.ToStart) != 1 || result.ToStart[0] != "new_collector" {
		t.Fatalf("expected toStart=['new_collector'], got %v", result.ToStart)
	}
	if len(result.ToRestart) != 1 || result.ToRestart[0] != "docker" {
		t.Fatalf("expected toRestart=['docker'], got %v", result.ToRestart)
	}
}

func TestComputeDiff_SortedOutput(t *testing.T) {
	entries := []collector.CollectorEntry{
		{Name: "zebra"},
		{Name: "alpha"},
		{Name: "middle"},
	}
	result := collector.ComputeDiff(nil, entries)
	if result.ToStart[0] != "alpha" || result.ToStart[1] != "middle" || result.ToStart[2] != "zebra" {
		t.Fatalf("expected sorted output, got %v", result.ToStart)
	}
}

func TestDigestConfig_Deterministic(t *testing.T) {
	h1 := collector.DigestConfig(map[string]string{"a": "1"})
	h2 := collector.DigestConfig(map[string]string{"a": "1"})
	h3 := collector.DigestConfig(map[string]string{"a": "2"})

	if h1 != h2 {
		t.Fatal("same input should produce same hash")
	}
	if h1 == h3 {
		t.Fatal("different input should produce different hash")
	}
}

func TestDigestConfig_Nil(t *testing.T) {
	h := collector.DigestConfig(nil)
	var zero collector.ConfigDigest
	if h == zero {
		t.Fatal("expected non-zero hash for nil (json.Marshal(nil) succeeds)")
	}
}

func TestDigestConfig_Unmarshallable(t *testing.T) {
	h := collector.DigestConfig(make(chan int))
	var zero collector.ConfigDigest
	if h != zero {
		t.Fatal("expected zero hash for unmarshallable value")
	}
	_ = json.Unmarshal // keep import
}

func TestComputeDiff_EmptyDesiredWithRunning(t *testing.T) {
	fsms := makeTestFSMs("a", "b", "c")
	result := collector.ComputeDiff(fsms, nil)
	if len(result.ToStop) != 3 {
		t.Fatalf("expected 3 toStop, got %d", len(result.ToStop))
	}
	if len(result.ToStart) != 0 || len(result.ToRestart) != 0 {
		t.Fatal("expected 0 toStart and toRestart")
	}
}

func TestComputeDiff_IdenticalConfigHash(t *testing.T) {
	hash := collector.DigestConfig("x")
	fsms := makeTestFSMs("a", "b")
	fsms["a"].SetConfigHash(hash)
	fsms["b"].SetConfigHash(hash)

	entries := []collector.CollectorEntry{
		{Name: "a", ConfigHash: hash},
		{Name: "b", ConfigHash: hash},
	}
	result := collector.ComputeDiff(fsms, entries)
	assertDiffEmpty(t, result)
}
