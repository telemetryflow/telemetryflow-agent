// Package all blank-imports every foundation processor so the registry is
// populated when cmd/tfo-agent pulls in this package. Mirrors the Telegraf
// plugins/processors/all pattern.
package all

import (
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/converter"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/defaults"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/drop"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/enum"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/filter"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/grok_parser"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/json_parser"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/keep"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/multiline"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/regex_parser"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/rename"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/starlark"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/tail_sampling"
)
