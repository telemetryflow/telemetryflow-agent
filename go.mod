module github.com/telemetryflow/telemetryflow-agent

go 1.26

// =============================================================================
// Direct Dependencies
// =============================================================================
require (
	// -------------------------------------------------------------------------
	// eBPF & System Monitoring
	// -------------------------------------------------------------------------
	github.com/cilium/ebpf v0.20.0 // eBPF kernel-level observability

	// -------------------------------------------------------------------------
	// CLI & Configuration
	// -------------------------------------------------------------------------
	github.com/google/uuid v1.6.0 // UUID generation for agent ID

	// -------------------------------------------------------------------------
	// Docker & Container Monitoring
	// -------------------------------------------------------------------------
	github.com/moby/moby/api v1.53.0 // Docker Engine API types
	github.com/moby/moby/client v0.2.2 // Docker client

	// -------------------------------------------------------------------------
	// Prometheus Integration
	// -------------------------------------------------------------------------
	github.com/prometheus/client_golang v1.23.2 // Prometheus client
	github.com/prometheus/client_model v0.6.2 // Prometheus data model
	github.com/prometheus/common v0.67.5 // Prometheus common utilities
	github.com/shirou/gopsutil/v3 v3.24.5 // System metrics (CPU, memory, disk, network)
	github.com/spf13/cobra v1.10.2 // CLI framework
	github.com/spf13/viper v1.21.0 // Configuration management

	// -------------------------------------------------------------------------
	// Testing
	// -------------------------------------------------------------------------
	github.com/stretchr/testify v1.11.1 // Test assertions

	// -------------------------------------------------------------------------
	// OpenTelemetry SDK v1.40.0
	// See: https://github.com/open-telemetry/opentelemetry-go
	// -------------------------------------------------------------------------
	go.opentelemetry.io/otel v1.43.0 // OTEL core API

	// -------------------------------------------------------------------------
	// OpenTelemetry Exporters - OTLP gRPC
	// -------------------------------------------------------------------------
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc v0.16.0 // OTLP log exporter (gRPC)

	// -------------------------------------------------------------------------
	// OpenTelemetry Exporters - OTLP HTTP
	// -------------------------------------------------------------------------
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.19.0 // OTLP log exporter (HTTP)
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.40.0 // OTLP metric exporter (gRPC)
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.40.0 // OTLP metric exporter (HTTP)
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.40.0 // OTLP trace exporter (gRPC)
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.40.0 // OTLP trace exporter (HTTP)
	go.opentelemetry.io/otel/metric v1.43.0 // OTEL metrics API
	go.opentelemetry.io/otel/sdk v1.43.0 // OTEL SDK
	go.opentelemetry.io/otel/sdk/log v0.19.0 // OTEL log SDK
	go.opentelemetry.io/otel/sdk/metric v1.43.0 // OTEL metric SDK
	go.opentelemetry.io/otel/trace v1.43.0 // OTEL trace API

	// -------------------------------------------------------------------------
	// Logging & gRPC
	// -------------------------------------------------------------------------
	go.uber.org/zap v1.27.1 // Structured logging
	google.golang.org/grpc v1.80.0 // gRPC support
	gopkg.in/yaml.v3 v3.0.1 // YAML parsing

	// -------------------------------------------------------------------------
	// Kubernetes Monitoring
	// -------------------------------------------------------------------------
	k8s.io/api v0.35.1 // Kubernetes API types
	k8s.io/apimachinery v0.35.1 // Kubernetes API machinery
	k8s.io/client-go v0.35.1 // Kubernetes client
	k8s.io/metrics v0.35.1 // Kubernetes metrics API
)

// =============================================================================
// Indirect Dependencies (auto-managed by go mod tidy)
// These are transitive dependencies required by the direct dependencies above.
// Do not modify manually - run 'go mod tidy' to update.
// =============================================================================
require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.6.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/emicklei/go-restful/v3 v3.12.2 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-openapi/jsonpointer v0.22.4 // indirect
	github.com/go-openapi/jsonreference v0.21.4 // indirect
	github.com/go-openapi/swag v0.25.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/google/gnostic-models v0.7.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.65.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.40.0 // indirect
	go.opentelemetry.io/otel/log v0.19.0 // indirect
	go.opentelemetry.io/proto/otlp v1.10.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/term v0.41.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260401024825-9d38bb4040a9 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260401024825-9d38bb4040a9 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20250910181357-589584f1c912 // indirect
	k8s.io/utils v0.0.0-20251002143259-bc988d571ff4 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

require (
	github.com/golang/snappy v1.0.0
	github.com/prometheus/prometheus v0.310.0
)

require (
	github.com/go-openapi/swag/cmdutils v0.25.4 // indirect
	github.com/go-openapi/swag/conv v0.25.4 // indirect
	github.com/go-openapi/swag/fileutils v0.25.4 // indirect
	github.com/go-openapi/swag/jsonname v0.25.4 // indirect
	github.com/go-openapi/swag/jsonutils v0.25.4 // indirect
	github.com/go-openapi/swag/loading v0.25.4 // indirect
	github.com/go-openapi/swag/mangling v0.25.4 // indirect
	github.com/go-openapi/swag/netutils v0.25.4 // indirect
	github.com/go-openapi/swag/stringutils v0.25.4 // indirect
	github.com/go-openapi/swag/typeutils v0.25.4 // indirect
	github.com/go-openapi/swag/yamlutils v0.25.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/grafana/regexp v0.0.0-20250905093917-f7b3be9d1853 // indirect
)
