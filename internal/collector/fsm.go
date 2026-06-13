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
)

type CollectorState string

const (
	StateNew      CollectorState = "new"
	StateStarting CollectorState = "starting"
	StateRunning  CollectorState = "running"
	StateStopping CollectorState = "stopping"
	StateStopped  CollectorState = "stopped"
	StateFailed   CollectorState = "failed"
	StateBackoff  CollectorState = "backoff"
)

func (s CollectorState) String() string { return string(s) }

type CollectorFSM struct {
	name       string
	collector  Collector
	state      CollectorState
	logger     *zap.Logger
	backoff    *Backoff
	mu         sync.RWMutex
	configHash ConfigDigest

	maxRetries int

	startedAt    time.Time
	lastError    error
	failureCount int
}

type FSMConfig struct {
	MaxStartRetries   int
	BackoffInitial    time.Duration
	BackoffMax        time.Duration
	BackoffMultiplier float64
}

func NewCollectorFSM(name string, c Collector, cfg FSMConfig, logger *zap.Logger) *CollectorFSM {
	return &CollectorFSM{
		name:       name,
		collector:  c,
		state:      StateNew,
		logger:     logger.With(zap.String("collector", name)),
		backoff:    NewBackoff(cfg.BackoffInitial, cfg.BackoffMax, cfg.BackoffMultiplier),
		maxRetries: cfg.MaxStartRetries,
	}
}

func (f *CollectorFSM) Name() string { return f.name }

func (f *CollectorFSM) State() CollectorState {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.state
}

func (f *CollectorFSM) StartedAt() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.startedAt
}

func (f *CollectorFSM) LastError() error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.lastError
}

func (f *CollectorFSM) FailureCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.failureCount
}

func (f *CollectorFSM) Collector() Collector {
	return f.collector
}

func (f *CollectorFSM) ConfigHash() ConfigDigest {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.configHash
}

func (f *CollectorFSM) SetConfigHash(h ConfigDigest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configHash = h
}

func (f *CollectorFSM) Start(ctx context.Context) error {
	f.mu.Lock()
	switch f.state {
	case StateRunning, StateStarting:
		f.mu.Unlock()
		return nil
	case StateNew, StateStopped, StateFailed, StateBackoff:
	default:
		f.mu.Unlock()
		return fmt.Errorf("cannot start collector %q in state %s", f.name, f.state)
	}
	f.state = StateStarting
	f.mu.Unlock()

	err := f.collector.Start(ctx)

	f.mu.Lock()
	defer f.mu.Unlock()

	if err != nil {
		f.lastError = err
		f.failureCount++
		if f.failureCount >= f.maxRetries {
			f.state = StateFailed
			f.logger.Error("collector failed after max retries",
				zap.Int("retries", f.failureCount),
				zap.Error(err),
			)
		} else {
			f.state = StateBackoff
			f.logger.Warn("collector start failed, will retry",
				zap.Int("attempt", f.failureCount),
				zap.Error(err),
			)
		}
		return err
	}

	f.state = StateRunning
	f.startedAt = time.Now()
	f.lastError = nil
	f.failureCount = 0
	f.backoff.Reset()
	f.logger.Info("collector started")
	return nil
}

func (f *CollectorFSM) Stop() error {
	f.mu.Lock()
	switch f.state {
	case StateRunning, StateBackoff, StateFailed:
	default:
		f.mu.Unlock()
		return nil
	}
	f.state = StateStopping
	f.mu.Unlock()

	err := f.collector.Stop()

	f.mu.Lock()
	defer f.mu.Unlock()

	if err != nil {
		f.lastError = err
		f.state = StateFailed
		f.logger.Error("collector stop failed", zap.Error(err))
		return err
	}

	f.state = StateStopped
	f.logger.Info("collector stopped")
	return nil
}

func (f *CollectorFSM) IsRunning() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.state == StateRunning
}

func (f *CollectorFSM) ShouldRetry() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.state == StateBackoff && f.failureCount < f.maxRetries
}

func (f *CollectorFSM) BackoffDuration() time.Duration {
	return f.backoff.Next()
}

func (f *CollectorFSM) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = StateNew
	f.failureCount = 0
	f.lastError = nil
	f.backoff.Reset()
}

type CollectorStatus struct {
	Name         string         `json:"name"`
	State        CollectorState `json:"state"`
	StartedAt    time.Time      `json:"started_at,omitempty"`
	LastError    string         `json:"last_error,omitempty"`
	FailureCount int            `json:"failure_count"`
}

func (f *CollectorFSM) Status() CollectorStatus {
	f.mu.RLock()
	defer f.mu.RUnlock()

	s := CollectorStatus{
		Name:         f.name,
		State:        f.state,
		StartedAt:    f.startedAt,
		FailureCount: f.failureCount,
	}
	if f.lastError != nil {
		s.LastError = f.lastError.Error()
	}
	return s
}
