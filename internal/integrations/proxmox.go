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

// ProxmoxConfig contains Proxmox VE integration configuration
type ProxmoxConfig struct {
	Enabled           bool              `mapstructure:"enabled"`
	APIUrl            string            `mapstructure:"api_url"`
	Username          string            `mapstructure:"username"`
	Password          string            `mapstructure:"password"`
	TokenID           string            `mapstructure:"token_id"`
	TokenSecret       string            `mapstructure:"token_secret"`
	Realm             string            `mapstructure:"realm"`
	Node              string            `mapstructure:"node"`
	TLSSkipVerify     bool              `mapstructure:"tls_skip_verify"`
	Timeout           time.Duration     `mapstructure:"timeout"`
	ScrapeInterval    time.Duration     `mapstructure:"scrape_interval"`
	CollectVMs        bool              `mapstructure:"collect_vms"`
	CollectContainers bool              `mapstructure:"collect_containers"`
	CollectStorage    bool              `mapstructure:"collect_storage"`
	CollectNetwork    bool              `mapstructure:"collect_network"`
	CollectCluster    bool              `mapstructure:"collect_cluster"`
	Headers           map[string]string `mapstructure:"headers"`
	Labels            map[string]string `mapstructure:"labels"`
}

// ProxmoxExporter exports telemetry data from/to Proxmox VE
type ProxmoxExporter struct {
	*BaseExporter
	config     ProxmoxConfig
	httpClient *http.Client
	authTicket string
	csrfToken  string
}

// Proxmox API response structures
type proxmoxResponse struct {
	Data interface{} `json:"data"`
}

type proxmoxNodeStatus struct {
	Uptime        int64         `json:"uptime"`
	CPU           float64       `json:"cpu"`
	Memory        proxmoxMemory `json:"memory"`
	RootFS        proxmoxDisk   `json:"rootfs"`
	Swap          proxmoxMemory `json:"swap"`
	LoadAvg       []float64     `json:"loadavg"`
	KernelVersion string        `json:"kversion"`
}

type proxmoxMemory struct {
	Used  int64 `json:"used"`
	Free  int64 `json:"free"`
	Total int64 `json:"total"`
}

type proxmoxDisk struct {
	Used  int64 `json:"used"`
	Avail int64 `json:"avail"`
	Total int64 `json:"total"`
}

type proxmoxVM struct {
	VMID      int     `json:"vmid"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	CPU       float64 `json:"cpu"`
	Mem       int64   `json:"mem"`
	MaxMem    int64   `json:"maxmem"`
	Disk      int64   `json:"disk"`
	MaxDisk   int64   `json:"maxdisk"`
	Uptime    int64   `json:"uptime"`
	NetIn     int64   `json:"netin"`
	NetOut    int64   `json:"netout"`
	DiskRead  int64   `json:"diskread"`
	DiskWrite int64   `json:"diskwrite"`
}

type proxmoxStorage struct {
	Storage string `json:"storage"`
	Type    string `json:"type"`
	Used    int64  `json:"used"`
	Avail   int64  `json:"avail"`
	Total   int64  `json:"total"`
	Active  int    `json:"active"`
}

// NewProxmoxExporter creates a new Proxmox VE exporter
func NewProxmoxExporter(config ProxmoxConfig, logger *zap.Logger) *ProxmoxExporter {
	return &ProxmoxExporter{
		BaseExporter: NewBaseExporter(
			"proxmox",
			"infrastructure",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the Proxmox exporter
func (p *ProxmoxExporter) Init(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}

	if err := p.Validate(); err != nil {
		return err
	}

	// Set defaults
	if p.config.Realm == "" {
		p.config.Realm = "pam"
	}
	if p.config.Timeout == 0 {
		p.config.Timeout = 30 * time.Second
	}
	if p.config.ScrapeInterval == 0 {
		p.config.ScrapeInterval = 30 * time.Second
	}
	if !p.config.CollectVMs && !p.config.CollectContainers && !p.config.CollectStorage && !p.config.CollectNetwork {
		// Enable all by default
		p.config.CollectVMs = true
		p.config.CollectContainers = true
		p.config.CollectStorage = true
		p.config.CollectNetwork = true
	}

	// Create HTTP client with optional TLS skip verify
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	if p.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in Proxmox VE deployments)
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	p.httpClient = &http.Client{
		Transport: transport,
		Timeout:   p.config.Timeout,
	}

	// Authenticate if using username/password
	if p.config.Username != "" && p.config.Password != "" {
		if err := p.authenticate(ctx); err != nil {
			return err
		}
	}

	p.SetInitialized(true)
	p.Logger().Info("Proxmox exporter initialized",
		zap.String("apiUrl", p.config.APIUrl),
		zap.String("node", p.config.Node),
	)

	return nil
}

// Validate validates the Proxmox configuration
func (p *ProxmoxExporter) Validate() error {
	if !p.config.Enabled {
		return nil
	}

	if p.config.APIUrl == "" {
		return NewValidationError("proxmox", "api_url", "api_url is required")
	}

	// Check for authentication method
	hasPassword := p.config.Username != "" && p.config.Password != ""
	hasToken := p.config.TokenID != "" && p.config.TokenSecret != ""

	if !hasPassword && !hasToken {
		return NewValidationError("proxmox", "auth", "either username/password or token_id/token_secret is required")
	}

	return nil
}

// Export exports telemetry data from Proxmox
func (p *ProxmoxExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !p.config.Enabled {
		return nil, ErrNotEnabled
	}

	// Proxmox is primarily a pull-based system - we collect metrics from it
	metrics, err := p.CollectMetrics(ctx)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	data.Metrics = append(data.Metrics, metrics...)

	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
	}, nil
}

// ExportMetrics is not applicable for Proxmox (it's a data source, not a destination)
func (p *ProxmoxExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("proxmox is a data source, not a metrics destination")
}

// ExportTraces is not supported by Proxmox
func (p *ProxmoxExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("proxmox does not support traces")
}

// ExportLogs is not supported by Proxmox
func (p *ProxmoxExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("proxmox does not support log ingestion")
}

// CollectMetrics collects metrics from Proxmox VE
func (p *ProxmoxExporter) CollectMetrics(ctx context.Context) ([]Metric, error) {
	if !p.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !p.IsInitialized() {
		return nil, ErrNotInitialized
	}

	var metrics []Metric
	now := time.Now()

	// Collect node metrics
	nodeMetrics, err := p.collectNodeMetrics(ctx, now)
	if err != nil {
		p.Logger().Warn("Failed to collect node metrics", zap.Error(err))
	} else {
		metrics = append(metrics, nodeMetrics...)
	}

	// Collect VM metrics
	if p.config.CollectVMs {
		vmMetrics, err := p.collectVMMetrics(ctx, now)
		if err != nil {
			p.Logger().Warn("Failed to collect VM metrics", zap.Error(err))
		} else {
			metrics = append(metrics, vmMetrics...)
		}
	}

	// Collect container metrics
	if p.config.CollectContainers {
		lxcMetrics, err := p.collectContainerMetrics(ctx, now)
		if err != nil {
			p.Logger().Warn("Failed to collect container metrics", zap.Error(err))
		} else {
			metrics = append(metrics, lxcMetrics...)
		}
	}

	// Collect storage metrics
	if p.config.CollectStorage {
		storageMetrics, err := p.collectStorageMetrics(ctx, now)
		if err != nil {
			p.Logger().Warn("Failed to collect storage metrics", zap.Error(err))
		} else {
			metrics = append(metrics, storageMetrics...)
		}
	}

	return metrics, nil
}

// collectNodeMetrics collects metrics from the Proxmox node
func (p *ProxmoxExporter) collectNodeMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	endpoint := fmt.Sprintf("%s/api2/json/nodes/%s/status", p.config.APIUrl, p.config.Node)

	body, err := p.apiRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var resp proxmoxResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	// Parse node status
	statusData, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, err
	}

	var status proxmoxNodeStatus
	if err := json.Unmarshal(statusData, &status); err != nil {
		return nil, err
	}

	baseTags := map[string]string{
		"node": p.config.Node,
	}
	for k, v := range p.config.Labels {
		baseTags[k] = v
	}

	metrics := []Metric{
		{Name: "proxmox_node_uptime_seconds", Value: float64(status.Uptime), Type: MetricTypeGauge, Timestamp: now, Tags: baseTags, Unit: "seconds"},
		{Name: "proxmox_node_cpu_usage", Value: status.CPU, Type: MetricTypeGauge, Timestamp: now, Tags: baseTags},
		{Name: "proxmox_node_memory_used_bytes", Value: float64(status.Memory.Used), Type: MetricTypeGauge, Timestamp: now, Tags: baseTags, Unit: "bytes"},
		{Name: "proxmox_node_memory_total_bytes", Value: float64(status.Memory.Total), Type: MetricTypeGauge, Timestamp: now, Tags: baseTags, Unit: "bytes"},
		{Name: "proxmox_node_memory_free_bytes", Value: float64(status.Memory.Free), Type: MetricTypeGauge, Timestamp: now, Tags: baseTags, Unit: "bytes"},
		{Name: "proxmox_node_swap_used_bytes", Value: float64(status.Swap.Used), Type: MetricTypeGauge, Timestamp: now, Tags: baseTags, Unit: "bytes"},
		{Name: "proxmox_node_swap_total_bytes", Value: float64(status.Swap.Total), Type: MetricTypeGauge, Timestamp: now, Tags: baseTags, Unit: "bytes"},
		{Name: "proxmox_node_rootfs_used_bytes", Value: float64(status.RootFS.Used), Type: MetricTypeGauge, Timestamp: now, Tags: baseTags, Unit: "bytes"},
		{Name: "proxmox_node_rootfs_total_bytes", Value: float64(status.RootFS.Total), Type: MetricTypeGauge, Timestamp: now, Tags: baseTags, Unit: "bytes"},
	}

	// Add load averages
	if len(status.LoadAvg) >= 3 {
		metrics = append(metrics,
			Metric{Name: "proxmox_node_load1", Value: status.LoadAvg[0], Type: MetricTypeGauge, Timestamp: now, Tags: baseTags},
			Metric{Name: "proxmox_node_load5", Value: status.LoadAvg[1], Type: MetricTypeGauge, Timestamp: now, Tags: baseTags},
			Metric{Name: "proxmox_node_load15", Value: status.LoadAvg[2], Type: MetricTypeGauge, Timestamp: now, Tags: baseTags},
		)
	}

	return metrics, nil
}

// collectVMMetrics collects metrics from QEMU VMs
func (p *ProxmoxExporter) collectVMMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	endpoint := fmt.Sprintf("%s/api2/json/nodes/%s/qemu", p.config.APIUrl, p.config.Node)

	body, err := p.apiRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var resp proxmoxResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	// Parse VM list
	vmData, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, err
	}

	var vms []proxmoxVM
	if err := json.Unmarshal(vmData, &vms); err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, vm := range vms {
		tags := map[string]string{
			"node":   p.config.Node,
			"vmid":   fmt.Sprintf("%d", vm.VMID),
			"name":   vm.Name,
			"status": vm.Status,
			"type":   "qemu",
		}
		for k, v := range p.config.Labels {
			tags[k] = v
		}

		running := 0.0
		if vm.Status == "running" {
			running = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "proxmox_vm_running", Value: running, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "proxmox_vm_cpu_usage", Value: vm.CPU, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "proxmox_vm_memory_used_bytes", Value: float64(vm.Mem), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_vm_memory_max_bytes", Value: float64(vm.MaxMem), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_vm_disk_used_bytes", Value: float64(vm.Disk), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_vm_disk_max_bytes", Value: float64(vm.MaxDisk), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_vm_uptime_seconds", Value: float64(vm.Uptime), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "seconds"},
			Metric{Name: "proxmox_vm_network_in_bytes", Value: float64(vm.NetIn), Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_vm_network_out_bytes", Value: float64(vm.NetOut), Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_vm_disk_read_bytes", Value: float64(vm.DiskRead), Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_vm_disk_write_bytes", Value: float64(vm.DiskWrite), Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
		)
	}

	return metrics, nil
}

// collectContainerMetrics collects metrics from LXC containers
func (p *ProxmoxExporter) collectContainerMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	endpoint := fmt.Sprintf("%s/api2/json/nodes/%s/lxc", p.config.APIUrl, p.config.Node)

	body, err := p.apiRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var resp proxmoxResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	// Parse container list
	lxcData, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, err
	}

	var containers []proxmoxVM
	if err := json.Unmarshal(lxcData, &containers); err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, ct := range containers {
		tags := map[string]string{
			"node":   p.config.Node,
			"vmid":   fmt.Sprintf("%d", ct.VMID),
			"name":   ct.Name,
			"status": ct.Status,
			"type":   "lxc",
		}
		for k, v := range p.config.Labels {
			tags[k] = v
		}

		running := 0.0
		if ct.Status == "running" {
			running = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "proxmox_container_running", Value: running, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "proxmox_container_cpu_usage", Value: ct.CPU, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "proxmox_container_memory_used_bytes", Value: float64(ct.Mem), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_container_memory_max_bytes", Value: float64(ct.MaxMem), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_container_disk_used_bytes", Value: float64(ct.Disk), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_container_disk_max_bytes", Value: float64(ct.MaxDisk), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_container_uptime_seconds", Value: float64(ct.Uptime), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "seconds"},
			Metric{Name: "proxmox_container_network_in_bytes", Value: float64(ct.NetIn), Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_container_network_out_bytes", Value: float64(ct.NetOut), Type: MetricTypeCounter, Timestamp: now, Tags: tags, Unit: "bytes"},
		)
	}

	return metrics, nil
}

// collectStorageMetrics collects metrics from storage pools
func (p *ProxmoxExporter) collectStorageMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	endpoint := fmt.Sprintf("%s/api2/json/nodes/%s/storage", p.config.APIUrl, p.config.Node)

	body, err := p.apiRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	var resp proxmoxResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	// Parse storage list
	storageData, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, err
	}

	var storages []proxmoxStorage
	if err := json.Unmarshal(storageData, &storages); err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, st := range storages {
		tags := map[string]string{
			"node":    p.config.Node,
			"storage": st.Storage,
			"type":    st.Type,
		}
		for k, v := range p.config.Labels {
			tags[k] = v
		}

		active := 0.0
		if st.Active == 1 {
			active = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "proxmox_storage_active", Value: active, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "proxmox_storage_used_bytes", Value: float64(st.Used), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_storage_available_bytes", Value: float64(st.Avail), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
			Metric{Name: "proxmox_storage_total_bytes", Value: float64(st.Total), Type: MetricTypeGauge, Timestamp: now, Tags: tags, Unit: "bytes"},
		)
	}

	return metrics, nil
}

// authenticate performs authentication with Proxmox API
func (p *ProxmoxExporter) authenticate(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/api2/json/access/ticket", p.config.APIUrl)

	data := url.Values{}
	data.Set("username", fmt.Sprintf("%s@%s", p.config.Username, p.config.Realm))
	data.Set("password", p.config.Password)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var authResp struct {
		Data struct {
			Ticket              string `json:"ticket"`
			CSRFPreventionToken string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return err
	}

	p.authTicket = authResp.Data.Ticket
	p.csrfToken = authResp.Data.CSRFPreventionToken

	return nil
}

// apiRequest makes an authenticated request to the Proxmox API
func (p *ProxmoxExporter) apiRequest(ctx context.Context, method, endpoint string, body []byte) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, err
	}

	// Set authentication
	if p.config.TokenID != "" && p.config.TokenSecret != "" {
		// API token authentication
		req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s@%s!%s=%s",
			p.config.Username, p.config.Realm, p.config.TokenID, p.config.TokenSecret))
	} else if p.authTicket != "" {
		// Cookie authentication
		req.AddCookie(&http.Cookie{
			Name:  "PVEAuthCookie",
			Value: p.authTicket,
		})
		if method != "GET" && p.csrfToken != "" {
			req.Header.Set("CSRFPreventionToken", p.csrfToken)
		}
	}

	// Add custom headers
	for k, v := range p.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("proxmox API error: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return io.ReadAll(resp.Body)
}

// Health checks the health of Proxmox connectivity
func (p *ProxmoxExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !p.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Check node status
	endpoint := fmt.Sprintf("%s/api2/json/nodes/%s/status", p.config.APIUrl, p.config.Node)
	_, err := p.apiRequest(ctx, "GET", endpoint, nil)
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
		Message:   "Proxmox connected",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"api_url": p.config.APIUrl,
			"node":    p.config.Node,
		},
	}, nil
}

// Close closes the Proxmox exporter
func (p *ProxmoxExporter) Close(ctx context.Context) error {
	if p.httpClient != nil {
		p.httpClient.CloseIdleConnections()
	}
	p.SetInitialized(false)
	p.Logger().Info("Proxmox exporter closed")
	return nil
}
