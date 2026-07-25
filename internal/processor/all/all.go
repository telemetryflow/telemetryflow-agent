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
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/keep"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/rename"
	_ "github.com/telemetryflow/telemetryflow-agent/internal/processor/starlark"
)
