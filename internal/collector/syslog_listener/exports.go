// Package syslog_listener exposes unexported symbols for external test packages.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
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

package syslog_listener

import (
	"fmt"
	"time"

	syslog "github.com/leodido/go-syslog/v4"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// LineSourceExported is the external-facing source abstraction. Each call to
// Next returns the bytes of one complete syslog message (a UDP datagram or a
// newline-delimited TCP/Unix line), or an error (io.EOF when exhausted).
//
// This is intentionally message-oriented rather than io.Reader-based: syslog
// over UDP is datagram-oriented and a Read(p []byte) stream contract does not
// map cleanly onto one-message-per-call semantics.
type LineSourceExported interface {
	Next() ([]byte, error)
	Close() error
}

// LineSourceFactoryExported builds a LineSourceExported for one listener.
// Tests inject a fake factory via SetLineSourceFactoryExported; production
// code uses defaultSourceFactory (real net.ListenUDP / net.Listen sockets).
type LineSourceFactoryExported func(lcfg config.SyslogListener) (LineSourceExported, error)

// SetLineSourceFactoryExported injects a test fake source factory. It must be
// called before Start(). Production code uses the default real-socket factory
// created in NewSyslogListenerCollector.
func (c *SyslogListenerCollector) SetLineSourceFactoryExported(fn LineSourceFactoryExported) {
	c.sourceFactory = fn
}

// WaitForReadersExported blocks until every background reader goroutine has
// exited (i.e. every source returned an error or io.EOF). This lets external
// tests feed lines through a fake source, wait for them to be processed, then
// assert on Collect() deterministically.
func (c *SyslogListenerCollector) WaitForReadersExported() {
	c.wg.Wait()
}

// CfgDefaultFormatExported returns the effective DefaultFormat applied by the
// constructor.
func (c *SyslogListenerCollector) CfgDefaultFormatExported() string { return c.cfg.DefaultFormat }

// CfgTimezoneExported returns the effective Timezone applied by the constructor.
func (c *SyslogListenerCollector) CfgTimezoneExported() string { return c.cfg.Timezone }

// CfgFlushIntervalExported returns the effective FlushInterval applied by the
// constructor.
func (c *SyslogListenerCollector) CfgFlushIntervalExported() time.Duration {
	return c.cfg.FlushInterval
}

// NewParserExported wraps newParser so external tests can exercise the
// format-to-parser mapping (including the unsupported-format error path)
// without touching the collector lifecycle.
func NewParserExported(format, timezone string) (syslog.Machine, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, fmt.Errorf("invalid timezone %q: %w", timezone, err)
	}
	return newParser(format, loc)
}

// SeverityLabelExported wraps severityLabel so external tests can verify the
// "informational" -> "info" normalization directly.
func SeverityLabelExported(msg syslog.Message) string { return severityLabel(msg) }

// FacilityLabelExported wraps facilityLabel so external tests can verify the
// facility label extraction directly.
func FacilityLabelExported(msg syslog.Message) string { return facilityLabel(msg) }
