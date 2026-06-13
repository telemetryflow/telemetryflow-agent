// Package collector defines the Collector interface and shared metric types
// used by every data-collection subsystem in the TelemetryFlow Agent.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
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
package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

type Manager struct {
	cfg     *config.SupervisorConfig
	logger  *zap.Logger
	mu      sync.RWMutex
	fsms    map[string]*CollectorFSM
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
}

func NewManager(cfg *config.SupervisorConfig, logger *zap.Logger) *Manager {
	return &Manager{
		cfg:    cfg,
		logger: logger.Named("supervisor"),
		fsms:   make(map[string]*CollectorFSM),
	}
}

func (m *Manager) Register(name string, c Collector, configHash ConfigDigest) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fsm := m.newFSM(name, c)
	fsm.SetConfigHash(configHash)
	m.fsms[name] = fsm
	m.logger.Info("collector registered", zap.String("name", name))
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.ctx, m.cancel = context.WithCancel(ctx)
	ctx = m.ctx
	m.mu.Unlock()

	for _, fsm := range m.fsms {
		go m.runFSM(ctx, fsm)
	}

	go m.runRetryLoop(ctx)

	m.logger.Info("supervisor started",
		zap.Int("collectors", len(m.fsms)),
	)
	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	if m.cancel != nil {
		m.cancel()
	}
	fsms := make([]*CollectorFSM, 0, len(m.fsms))
	for _, fsm := range m.fsms {
		fsms = append(fsms, fsm)
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, fsm := range fsms {
		wg.Add(1)
		go func(f *CollectorFSM) {
			defer wg.Done()
			_ = f.Stop()
		}(fsm)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		m.logger.Warn("supervisor stop timeout")
	}

	m.logger.Info("supervisor stopped")
	return nil
}

func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

func (m *Manager) CollectorStates() []CollectorStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make([]CollectorStatus, 0, len(m.fsms))
	for _, fsm := range m.fsms {
		states = append(states, fsm.Status())
	}
	return states
}

func (m *Manager) ApplyDiff(entries []CollectorEntry) error {
	m.mu.RLock()
	current := make(map[string]*CollectorFSM, len(m.fsms))
	for k, v := range m.fsms {
		current[k] = v
	}
	ctx := m.ctx
	m.mu.RUnlock()

	diff := ComputeDiff(current, entries)

	for _, name := range diff.ToStop {
		m.mu.Lock()
		if fsm, ok := m.fsms[name]; ok {
			_ = fsm.Stop()
			delete(m.fsms, name)
			m.mu.Unlock()
			m.logger.Info("collector removed", zap.String("name", name))
		} else {
			m.mu.Unlock()
		}
	}

	for _, name := range diff.ToRestart {
		m.mu.Lock()
		if fsm, ok := m.fsms[name]; ok {
			_ = fsm.Stop()
			fsm.Reset()
			for _, e := range entries {
				if e.Name == name {
					fsm.SetConfigHash(e.ConfigHash)
					break
				}
			}
			m.mu.Unlock()
			go m.runFSM(ctx, fsm)
			m.logger.Info("collector restarting (config changed)", zap.String("name", name))
		} else {
			m.mu.Unlock()
		}
	}

	for _, entry := range entries {
		m.mu.Lock()
		if _, ok := m.fsms[entry.Name]; !ok {
			fsm := m.newFSM(entry.Name, entry.Collector)
			fsm.SetConfigHash(entry.ConfigHash)
			m.fsms[entry.Name] = fsm
			m.mu.Unlock()
			go m.runFSM(ctx, fsm)
			m.logger.Info("collector added", zap.String("name", entry.Name))
		} else {
			m.mu.Unlock()
		}
	}

	return nil
}

func (m *Manager) newFSM(name string, c Collector) *CollectorFSM {
	return NewCollectorFSM(name, c, FSMConfig{
		MaxStartRetries:   m.cfg.FSM.MaxStartRetries,
		BackoffInitial:    m.cfg.FSM.BackoffInitial,
		BackoffMax:        m.cfg.FSM.BackoffMax,
		BackoffMultiplier: m.cfg.FSM.BackoffMultiplier,
	}, m.logger)
}

func (m *Manager) runFSM(ctx context.Context, fsm *CollectorFSM) {
	if err := fsm.Start(ctx); err != nil {
		m.logger.Warn("collector start failed",
			zap.String("name", fsm.Name()),
			zap.Error(err),
		)
	}
}

func (m *Manager) runRetryLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var toRetry []*CollectorFSM
		m.mu.RLock()
		for _, fsm := range m.fsms {
			if fsm.ShouldRetry() {
				copied := fsm
				toRetry = append(toRetry, copied)
			}
		}
		m.mu.RUnlock()

		for _, f := range toRetry {
			go func(fsm *CollectorFSM) {
				dur := fsm.BackoffDuration()
				m.logger.Info("retrying collector start",
					zap.String("name", fsm.Name()),
					zap.Duration("backoff", dur),
				)
				select {
				case <-time.After(dur):
				case <-ctx.Done():
					return
				}
				_ = fsm.Start(ctx)
			}(f)
		}
	}
}

func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := ManagerStats{
		Total: len(m.fsms),
	}
	for _, fsm := range m.fsms {
		switch fsm.State() {
		case StateRunning:
			stats.Running++
		case StateFailed:
			stats.Failed++
		case StateBackoff:
			stats.Backoff++
		case StateNew, StateStarting, StateStopping, StateStopped:
			stats.Stopped++
		}
	}
	return stats
}

type ManagerStats struct {
	Total   int `json:"total"`
	Running int `json:"running"`
	Failed  int `json:"failed"`
	Backoff int `json:"backoff"`
	Stopped int `json:"stopped"`
}

func (m *Manager) FormatStats() string {
	s := m.Stats()
	return fmt.Sprintf("total=%d running=%d failed=%d backoff=%d stopped=%d",
		s.Total, s.Running, s.Failed, s.Backoff, s.Stopped)
}
