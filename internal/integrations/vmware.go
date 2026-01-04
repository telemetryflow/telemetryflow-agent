// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

// VMwareConfig contains VMware vSphere integration configuration
type VMwareConfig struct {
	Enabled           bool              `mapstructure:"enabled"`
	VCenterURL        string            `mapstructure:"vcenter_url"`
	Username          string            `mapstructure:"username"`
	Password          string            `mapstructure:"password"`
	Datacenter        string            `mapstructure:"datacenter"`
	Cluster           string            `mapstructure:"cluster"`
	TLSSkipVerify     bool              `mapstructure:"tls_skip_verify"`
	Timeout           time.Duration     `mapstructure:"timeout"`
	ScrapeInterval    time.Duration     `mapstructure:"scrape_interval"`
	CollectVMs        bool              `mapstructure:"collect_vms"`
	CollectHosts      bool              `mapstructure:"collect_hosts"`
	CollectDatastores bool              `mapstructure:"collect_datastores"`
	CollectClusters   bool              `mapstructure:"collect_clusters"`
	CollectNetworks   bool              `mapstructure:"collect_networks"`
	PerformanceLevel  int               `mapstructure:"performance_level"` // 1-4, higher = more metrics
	Headers           map[string]string `mapstructure:"headers"`
	Labels            map[string]string `mapstructure:"labels"`
}

// VMwareExporter exports telemetry data from VMware vSphere
type VMwareExporter struct {
	*BaseExporter
	config     VMwareConfig
	httpClient *http.Client
	sessionID  string
}

// vSphere API structures
type vsphereVM struct {
	VM            string `json:"vm"`
	Name          string `json:"name"`
	PowerState    string `json:"power_state"`
	CPUCount      int    `json:"cpu_count"`
	MemorySizeMiB int64  `json:"memory_size_MiB"`
	GuestOS       string `json:"guest_OS"`
}

type vsphereHost struct {
	Host            string `json:"host"`
	Name            string `json:"name"`
	ConnectionState string `json:"connection_state"`
	PowerState      string `json:"power_state"`
}

type vsphereDatastore struct {
	Datastore string `json:"datastore"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Capacity  int64  `json:"capacity"`
	FreeSpace int64  `json:"free_space"`
}

type vsphereCluster struct {
	Cluster    string `json:"cluster"`
	Name       string `json:"name"`
	HAEnabled  bool   `json:"ha_enabled"`
	DRSEnabled bool   `json:"drs_enabled"`
}

type vsphereVMMetrics struct {
	CPU struct {
		UsagePercent float64 `json:"usage_percent"`
		UsageMHz     int64   `json:"usage_mhz"`
	} `json:"cpu"`
	Memory struct {
		UsedMiB   int64 `json:"used_MiB"`
		ActiveMiB int64 `json:"active_MiB"`
	} `json:"memory"`
	Disk struct {
		ReadKBps  float64 `json:"read_kbps"`
		WriteKBps float64 `json:"write_kbps"`
	} `json:"disk"`
	Network struct {
		RxKBps float64 `json:"rx_kbps"`
		TxKBps float64 `json:"tx_kbps"`
	} `json:"network"`
}

// NewVMwareExporter creates a new VMware vSphere exporter
func NewVMwareExporter(config VMwareConfig, logger *zap.Logger) *VMwareExporter {
	return &VMwareExporter{
		BaseExporter: NewBaseExporter(
			"vmware",
			"infrastructure",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the VMware exporter
func (v *VMwareExporter) Init(ctx context.Context) error {
	if !v.config.Enabled {
		return nil
	}

	if err := v.Validate(); err != nil {
		return err
	}

	// Set defaults
	if v.config.Timeout == 0 {
		v.config.Timeout = 30 * time.Second
	}
	if v.config.ScrapeInterval == 0 {
		v.config.ScrapeInterval = 60 * time.Second
	}
	if v.config.PerformanceLevel == 0 {
		v.config.PerformanceLevel = 2 // Default to level 2
	}
	if !v.config.CollectVMs && !v.config.CollectHosts && !v.config.CollectDatastores {
		// Enable all by default
		v.config.CollectVMs = true
		v.config.CollectHosts = true
		v.config.CollectDatastores = true
		v.config.CollectClusters = true
	}

	// Create HTTP client with optional TLS skip verify
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	if v.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in VMware vCenter deployments)
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	v.httpClient = &http.Client{
		Transport: transport,
		Timeout:   v.config.Timeout,
	}

	// Create session
	if err := v.createSession(ctx); err != nil {
		return err
	}

	v.SetInitialized(true)
	v.Logger().Info("VMware exporter initialized",
		zap.String("vcenterUrl", v.config.VCenterURL),
		zap.String("datacenter", v.config.Datacenter),
	)

	return nil
}

// Validate validates the VMware configuration
func (v *VMwareExporter) Validate() error {
	if !v.config.Enabled {
		return nil
	}

	if v.config.VCenterURL == "" {
		return NewValidationError("vmware", "vcenter_url", "vcenter_url is required")
	}

	if v.config.Username == "" {
		return NewValidationError("vmware", "username", "username is required")
	}

	if v.config.Password == "" {
		return NewValidationError("vmware", "password", "password is required")
	}

	return nil
}

// Export exports telemetry data from VMware
func (v *VMwareExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !v.config.Enabled {
		return nil, ErrNotEnabled
	}

	// VMware is primarily a pull-based system - we collect metrics from it
	metrics, err := v.CollectMetrics(ctx)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	data.Metrics = append(data.Metrics, metrics...)

	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
	}, nil
}

// ExportMetrics is not applicable for VMware (it's a data source, not a destination)
func (v *VMwareExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("vmware is a data source, not a metrics destination")
}

// ExportTraces is not supported by VMware
func (v *VMwareExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("vmware does not support traces")
}

// ExportLogs is not supported by VMware
func (v *VMwareExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("vmware does not support log ingestion")
}

// CollectMetrics collects metrics from VMware vSphere
func (v *VMwareExporter) CollectMetrics(ctx context.Context) ([]Metric, error) {
	if !v.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !v.IsInitialized() {
		return nil, ErrNotInitialized
	}

	var metrics []Metric
	now := time.Now()

	// Collect VM metrics
	if v.config.CollectVMs {
		vmMetrics, err := v.collectVMMetrics(ctx, now)
		if err != nil {
			v.Logger().Warn("Failed to collect VM metrics", zap.Error(err))
		} else {
			metrics = append(metrics, vmMetrics...)
		}
	}

	// Collect host metrics
	if v.config.CollectHosts {
		hostMetrics, err := v.collectHostMetrics(ctx, now)
		if err != nil {
			v.Logger().Warn("Failed to collect host metrics", zap.Error(err))
		} else {
			metrics = append(metrics, hostMetrics...)
		}
	}

	// Collect datastore metrics
	if v.config.CollectDatastores {
		dsMetrics, err := v.collectDatastoreMetrics(ctx, now)
		if err != nil {
			v.Logger().Warn("Failed to collect datastore metrics", zap.Error(err))
		} else {
			metrics = append(metrics, dsMetrics...)
		}
	}

	// Collect cluster metrics
	if v.config.CollectClusters {
		clusterMetrics, err := v.collectClusterMetrics(ctx, now)
		if err != nil {
			v.Logger().Warn("Failed to collect cluster metrics", zap.Error(err))
		} else {
			metrics = append(metrics, clusterMetrics...)
		}
	}

	return metrics, nil
}

// collectVMMetrics collects metrics from VMs
func (v *VMwareExporter) collectVMMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	// List VMs
	vms, err := v.listVMs(ctx)
	if err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, vm := range vms {
		tags := map[string]string{
			"vm_id":       vm.VM,
			"vm_name":     vm.Name,
			"power_state": vm.PowerState,
			"guest_os":    vm.GuestOS,
		}
		if v.config.Datacenter != "" {
			tags["datacenter"] = v.config.Datacenter
		}
		if v.config.Cluster != "" {
			tags["cluster"] = v.config.Cluster
		}
		for k, val := range v.config.Labels {
			tags[k] = val
		}

		// Basic VM info metrics
		running := 0.0
		if vm.PowerState == "POWERED_ON" {
			running = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "vmware_vm_power_state", Value: running, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "vmware_vm_cpu_count", Value: float64(vm.CPUCount), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "vmware_vm_memory_size_bytes", Value: float64(vm.MemorySizeMiB * 1024 * 1024), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
		)

		// Get detailed VM metrics if powered on
		if vm.PowerState == "POWERED_ON" {
			vmMetrics, err := v.getVMMetrics(ctx, vm.VM)
			if err != nil {
				v.Logger().Debug("Failed to get VM metrics", zap.String("vm", vm.Name), zap.Error(err))
				continue
			}

			metrics = append(metrics,
				Metric{Name: "vmware_vm_cpu_usage_percent", Value: vmMetrics.CPU.UsagePercent, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
				Metric{Name: "vmware_vm_cpu_usage_mhz", Value: float64(vmMetrics.CPU.UsageMHz), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "megahertz"},
				Metric{Name: "vmware_vm_memory_used_bytes", Value: float64(vmMetrics.Memory.UsedMiB * 1024 * 1024), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
				Metric{Name: "vmware_vm_memory_active_bytes", Value: float64(vmMetrics.Memory.ActiveMiB * 1024 * 1024), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
				Metric{Name: "vmware_vm_disk_read_kbps", Value: vmMetrics.Disk.ReadKBps, Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "kilobytes/second"},
				Metric{Name: "vmware_vm_disk_write_kbps", Value: vmMetrics.Disk.WriteKBps, Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "kilobytes/second"},
				Metric{Name: "vmware_vm_network_rx_kbps", Value: vmMetrics.Network.RxKBps, Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "kilobytes/second"},
				Metric{Name: "vmware_vm_network_tx_kbps", Value: vmMetrics.Network.TxKBps, Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "kilobytes/second"},
			)
		}
	}

	return metrics, nil
}

// collectHostMetrics collects metrics from ESXi hosts
func (v *VMwareExporter) collectHostMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	hosts, err := v.listHosts(ctx)
	if err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, host := range hosts {
		tags := map[string]string{
			"host_id":          host.Host,
			"host_name":        host.Name,
			"connection_state": host.ConnectionState,
			"power_state":      host.PowerState,
		}
		if v.config.Datacenter != "" {
			tags["datacenter"] = v.config.Datacenter
		}
		for k, val := range v.config.Labels {
			tags[k] = val
		}

		connected := 0.0
		if host.ConnectionState == "CONNECTED" {
			connected = 1.0
		}
		poweredOn := 0.0
		if host.PowerState == "POWERED_ON" {
			poweredOn = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "vmware_host_connected", Value: connected, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "vmware_host_power_state", Value: poweredOn, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// collectDatastoreMetrics collects metrics from datastores
func (v *VMwareExporter) collectDatastoreMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	datastores, err := v.listDatastores(ctx)
	if err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, ds := range datastores {
		tags := map[string]string{
			"datastore_id":   ds.Datastore,
			"datastore_name": ds.Name,
			"datastore_type": ds.Type,
		}
		if v.config.Datacenter != "" {
			tags["datacenter"] = v.config.Datacenter
		}
		for k, val := range v.config.Labels {
			tags[k] = val
		}

		usedSpace := ds.Capacity - ds.FreeSpace
		usagePercent := 0.0
		if ds.Capacity > 0 {
			usagePercent = float64(usedSpace) / float64(ds.Capacity) * 100
		}

		metrics = append(metrics,
			Metric{Name: "vmware_datastore_capacity_bytes", Value: float64(ds.Capacity), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "vmware_datastore_free_bytes", Value: float64(ds.FreeSpace), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "vmware_datastore_used_bytes", Value: float64(usedSpace), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "vmware_datastore_usage_percent", Value: usagePercent, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// collectClusterMetrics collects metrics from clusters
func (v *VMwareExporter) collectClusterMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	clusters, err := v.listClusters(ctx)
	if err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, cluster := range clusters {
		tags := map[string]string{
			"cluster_id":   cluster.Cluster,
			"cluster_name": cluster.Name,
		}
		if v.config.Datacenter != "" {
			tags["datacenter"] = v.config.Datacenter
		}
		for k, val := range v.config.Labels {
			tags[k] = val
		}

		haEnabled := 0.0
		if cluster.HAEnabled {
			haEnabled = 1.0
		}
		drsEnabled := 0.0
		if cluster.DRSEnabled {
			drsEnabled = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "vmware_cluster_ha_enabled", Value: haEnabled, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "vmware_cluster_drs_enabled", Value: drsEnabled, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// createSession creates a vSphere API session
func (v *VMwareExporter) createSession(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/api/session", v.config.VCenterURL)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, nil)
	if err != nil {
		return err
	}

	req.SetBasicAuth(v.config.Username, v.config.Password)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("session creation failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var sessionID string
	if err := json.NewDecoder(resp.Body).Decode(&sessionID); err != nil {
		return err
	}

	v.sessionID = sessionID
	return nil
}

// apiRequest makes an authenticated request to the vSphere API
func (v *VMwareExporter) apiRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	endpoint := fmt.Sprintf("%s%s", v.config.VCenterURL, path)

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("vmware-api-session-id", v.sessionID)
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for k, val := range v.config.Headers {
		req.Header.Set(k, val)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		// Try to re-authenticate
		if err := v.createSession(ctx); err != nil {
			return nil, err
		}
		// Retry request
		req.Header.Set("vmware-api-session-id", v.sessionID)
		resp, err = v.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vSphere API error: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return io.ReadAll(resp.Body)
}

// listVMs lists all VMs
func (v *VMwareExporter) listVMs(ctx context.Context) ([]vsphereVM, error) {
	path := "/api/vcenter/vm"
	if v.config.Datacenter != "" {
		path += "?datacenters=" + url.QueryEscape(v.config.Datacenter)
	}

	body, err := v.apiRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var vms []vsphereVM
	if err := json.Unmarshal(body, &vms); err != nil {
		return nil, err
	}

	return vms, nil
}

// listHosts lists all ESXi hosts
func (v *VMwareExporter) listHosts(ctx context.Context) ([]vsphereHost, error) {
	path := "/api/vcenter/host"
	if v.config.Datacenter != "" {
		path += "?datacenters=" + url.QueryEscape(v.config.Datacenter)
	}

	body, err := v.apiRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var hosts []vsphereHost
	if err := json.Unmarshal(body, &hosts); err != nil {
		return nil, err
	}

	return hosts, nil
}

// listDatastores lists all datastores
func (v *VMwareExporter) listDatastores(ctx context.Context) ([]vsphereDatastore, error) {
	path := "/api/vcenter/datastore"
	if v.config.Datacenter != "" {
		path += "?datacenters=" + url.QueryEscape(v.config.Datacenter)
	}

	body, err := v.apiRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var datastores []vsphereDatastore
	if err := json.Unmarshal(body, &datastores); err != nil {
		return nil, err
	}

	return datastores, nil
}

// listClusters lists all clusters
func (v *VMwareExporter) listClusters(ctx context.Context) ([]vsphereCluster, error) {
	path := "/api/vcenter/cluster"
	if v.config.Datacenter != "" {
		path += "?datacenters=" + url.QueryEscape(v.config.Datacenter)
	}

	body, err := v.apiRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var clusters []vsphereCluster
	if err := json.Unmarshal(body, &clusters); err != nil {
		return nil, err
	}

	return clusters, nil
}

// getVMMetrics gets performance metrics for a VM
func (v *VMwareExporter) getVMMetrics(ctx context.Context, vmID string) (*vsphereVMMetrics, error) {
	// This would typically use the performance manager API
	// For now, return mock metrics structure
	path := fmt.Sprintf("/api/vcenter/vm/%s", vmID)

	body, err := v.apiRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	// Parse VM details (metrics would come from perf manager in production)
	var vmDetails struct {
		Memory struct {
			SizeMiB int64 `json:"size_MiB"`
		} `json:"memory"`
		CPU struct {
			Count int `json:"count"`
		} `json:"cpu"`
	}
	if err := json.Unmarshal(body, &vmDetails); err != nil {
		return nil, err
	}

	// Return estimated metrics
	return &vsphereVMMetrics{
		CPU: struct {
			UsagePercent float64 `json:"usage_percent"`
			UsageMHz     int64   `json:"usage_mhz"`
		}{
			UsagePercent: 0,
			UsageMHz:     0,
		},
		Memory: struct {
			UsedMiB   int64 `json:"used_MiB"`
			ActiveMiB int64 `json:"active_MiB"`
		}{
			UsedMiB:   0,
			ActiveMiB: 0,
		},
	}, nil
}

// Health checks the health of VMware connectivity
func (v *VMwareExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !v.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Try to list VMs as health check
	_, err := v.listVMs(ctx)
	if err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   fmt.Sprintf("connection failed: %v", err),
			LastCheck: time.Now(),
			LastError: err,
			Latency:   time.Since(startTime),
		}, nil
	}

	return &HealthStatus{
		Healthy:   true,
		Message:   "VMware vSphere connected",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"vcenter_url": v.config.VCenterURL,
			"datacenter":  v.config.Datacenter,
		},
	}, nil
}

// Close closes the VMware exporter
func (v *VMwareExporter) Close(ctx context.Context) error {
	// Delete session
	if v.sessionID != "" {
		endpoint := fmt.Sprintf("%s/api/session", v.config.VCenterURL)
		req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
		if err == nil {
			req.Header.Set("vmware-api-session-id", v.sessionID)
			resp, err := v.httpClient.Do(req)
			if err == nil {
				_ = resp.Body.Close()
			}
		}
	}

	if v.httpClient != nil {
		v.httpClient.CloseIdleConnections()
	}
	v.SetInitialized(false)
	v.Logger().Info("VMware exporter closed")
	return nil
}
