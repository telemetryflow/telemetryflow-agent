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
	"time"

	"go.uber.org/zap"
)

// CiscoConfig contains Cisco integration configuration
type CiscoConfig struct {
	Enabled           bool              `mapstructure:"enabled"`
	DNACenterURL      string            `mapstructure:"dnac_url"`
	MerakiAPIKey      string            `mapstructure:"meraki_api_key"`
	MerakiBaseURL     string            `mapstructure:"meraki_base_url"` // defaults to https://api.meraki.com/api/v1
	Username          string            `mapstructure:"username"`
	Password          string            `mapstructure:"password"`
	APIType           string            `mapstructure:"api_type"` // dnac, meraki, ise, aci
	TLSSkipVerify     bool              `mapstructure:"tls_skip_verify"`
	Timeout           time.Duration     `mapstructure:"timeout"`
	ScrapeInterval    time.Duration     `mapstructure:"scrape_interval"`
	CollectDevices    bool              `mapstructure:"collect_devices"`
	CollectNetworks   bool              `mapstructure:"collect_networks"`
	CollectClients    bool              `mapstructure:"collect_clients"`
	CollectHealth     bool              `mapstructure:"collect_health"`
	CollectInterfaces bool              `mapstructure:"collect_interfaces"`
	Headers           map[string]string `mapstructure:"headers"`
	Labels            map[string]string `mapstructure:"labels"`
}

// CiscoExporter exports telemetry data from Cisco infrastructure
type CiscoExporter struct {
	*BaseExporter
	config      CiscoConfig
	httpClient  *http.Client
	authToken   string
	tokenExpiry time.Time
}

// Cisco DNA Center structures
type dnacDevice struct {
	ID                 string `json:"id"`
	Hostname           string `json:"hostname"`
	ManagementIPAddr   string `json:"managementIpAddress"`
	PlatformID         string `json:"platformId"`
	Family             string `json:"family"`
	Type               string `json:"type"`
	SoftwareVersion    string `json:"softwareVersion"`
	Role               string `json:"role"`
	SerialNumber       string `json:"serialNumber"`
	MacAddress         string `json:"macAddress"`
	UpTime             string `json:"upTime"`
	ReachabilityStatus string `json:"reachabilityStatus"`
	CollectionStatus   string `json:"collectionStatus"`
	MemorySize         string `json:"memorySize"`
	ErrorCode          string `json:"errorCode"`
	LastUpdated        string `json:"lastUpdated"`
}

type dnacHealth struct {
	NetworkHealth     []healthScore `json:"networkHealth"`
	ClientHealth      []healthScore `json:"clientHealth"`
	ApplicationHealth []healthScore `json:"applicationHealth"`
}

type healthScore struct {
	HealthType  string  `json:"healthType"`
	HealthScore float64 `json:"healthScore"`
	Category    string  `json:"category,omitempty"`
}

// Meraki structures
type merakiNetwork struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	OrganizationID string   `json:"organizationId"`
	TimeZone       string   `json:"timeZone"`
	ProductTypes   []string `json:"productTypes"`
}

type merakiDevice struct {
	Serial      string   `json:"serial"`
	Name        string   `json:"name"`
	Mac         string   `json:"mac"`
	NetworkID   string   `json:"networkId"`
	Model       string   `json:"model"`
	LanIP       string   `json:"lanIp"`
	Firmware    string   `json:"firmware"`
	ProductType string   `json:"productType"`
	Tags        []string `json:"tags"`
}

type merakiDeviceStatus struct {
	Serial         string `json:"serial"`
	Name           string `json:"name"`
	Status         string `json:"status"`
	LanIP          string `json:"lanIp"`
	PublicIP       string `json:"publicIp"`
	ProductType    string `json:"productType"`
	UsingCellular  bool   `json:"usingCellular"`
	LastReportedAt string `json:"lastReportedAt"`
}

// Ensure types are used (for future implementation)
var (
	_ = dnacHealth{}
	_ = healthScore{}
	_ = merakiNetwork{}
	_ = merakiDevice{}
)

// NewCiscoExporter creates a new Cisco exporter
func NewCiscoExporter(config CiscoConfig, logger *zap.Logger) *CiscoExporter {
	return &CiscoExporter{
		BaseExporter: NewBaseExporter(
			"cisco",
			"network",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the Cisco exporter
func (c *CiscoExporter) Init(ctx context.Context) error {
	if !c.config.Enabled {
		return nil
	}

	if err := c.Validate(); err != nil {
		return err
	}

	// Set defaults
	if c.config.APIType == "" {
		if c.config.MerakiAPIKey != "" {
			c.config.APIType = "meraki"
		} else {
			c.config.APIType = "dnac"
		}
	}
	if c.config.Timeout == 0 {
		c.config.Timeout = 30 * time.Second
	}
	if c.config.ScrapeInterval == 0 {
		c.config.ScrapeInterval = 60 * time.Second
	}
	if c.config.MerakiBaseURL == "" {
		c.config.MerakiBaseURL = "https://api.meraki.com/api/v1"
	}
	if !c.config.CollectDevices && !c.config.CollectNetworks && !c.config.CollectHealth {
		c.config.CollectDevices = true
		c.config.CollectNetworks = true
		c.config.CollectHealth = true
		c.config.CollectClients = true
	}

	// Create HTTP client
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	if c.config.TLSSkipVerify {
		// #nosec G402 -- InsecureSkipVerify is intentionally configurable for environments
		// with self-signed certificates (common in Cisco network deployments)
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   c.config.Timeout,
	}

	// Authenticate if using DNA Center
	if c.config.APIType == "dnac" && c.config.Username != "" {
		if err := c.authenticateDNAC(ctx); err != nil {
			return err
		}
	}

	c.SetInitialized(true)
	c.Logger().Info("Cisco exporter initialized",
		zap.String("apiType", c.config.APIType),
	)

	return nil
}

// Validate validates the Cisco configuration
func (c *CiscoExporter) Validate() error {
	if !c.config.Enabled {
		return nil
	}

	switch c.config.APIType {
	case "meraki", "":
		if c.config.MerakiAPIKey == "" && c.config.APIType == "meraki" {
			return NewValidationError("cisco", "meraki_api_key", "meraki_api_key is required for Meraki API")
		}
	case "dnac":
		if c.config.DNACenterURL == "" {
			return NewValidationError("cisco", "dnac_url", "dnac_url is required for DNA Center API")
		}
		if c.config.Username == "" || c.config.Password == "" {
			return NewValidationError("cisco", "credentials", "username and password are required for DNA Center")
		}
	}

	return nil
}

// Export exports telemetry data from Cisco
func (c *CiscoExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !c.config.Enabled {
		return nil, ErrNotEnabled
	}

	metrics, err := c.CollectMetrics(ctx)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	data.Metrics = append(data.Metrics, metrics...)

	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
	}, nil
}

// ExportMetrics is not applicable for Cisco (it's a data source)
func (c *CiscoExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("cisco is a data source, not a metrics destination")
}

// ExportTraces is not supported by Cisco
func (c *CiscoExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("cisco does not support traces")
}

// ExportLogs is not supported by Cisco
func (c *CiscoExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("cisco does not support log ingestion")
}

// CollectMetrics collects metrics from Cisco infrastructure
func (c *CiscoExporter) CollectMetrics(ctx context.Context) ([]Metric, error) {
	if !c.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !c.IsInitialized() {
		return nil, ErrNotInitialized
	}

	now := time.Now()

	switch c.config.APIType {
	case "meraki":
		return c.collectMerakiMetrics(ctx, now)
	case "dnac":
		return c.collectDNACMetrics(ctx, now)
	default:
		return nil, fmt.Errorf("unsupported API type: %s", c.config.APIType)
	}
}

// collectMerakiMetrics collects metrics from Meraki Dashboard
func (c *CiscoExporter) collectMerakiMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	var metrics []Metric

	// Get organization ID first (simplified - in production would list orgs)
	// Collect device statuses
	if c.config.CollectDevices {
		deviceMetrics, err := c.collectMerakiDevices(ctx, now)
		if err != nil {
			c.Logger().Warn("Failed to collect Meraki device metrics", zap.Error(err))
		} else {
			metrics = append(metrics, deviceMetrics...)
		}
	}

	return metrics, nil
}

// collectMerakiDevices collects device metrics from Meraki
func (c *CiscoExporter) collectMerakiDevices(ctx context.Context, now time.Time) ([]Metric, error) {
	// Get organizations
	orgsBody, err := c.merakiRequest(ctx, "GET", "/organizations", nil)
	if err != nil {
		return nil, err
	}

	var orgs []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(orgsBody, &orgs); err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, org := range orgs {
		// Get device statuses
		path := fmt.Sprintf("/organizations/%s/devices/statuses", org.ID)
		statusBody, err := c.merakiRequest(ctx, "GET", path, nil)
		if err != nil {
			c.Logger().Warn("Failed to get device statuses", zap.String("org", org.Name), zap.Error(err))
			continue
		}

		var statuses []merakiDeviceStatus
		if err := json.Unmarshal(statusBody, &statuses); err != nil {
			continue
		}

		for _, device := range statuses {
			tags := map[string]string{
				"organization": org.Name,
				"serial":       device.Serial,
				"name":         device.Name,
				"product_type": device.ProductType,
				"status":       device.Status,
			}
			for k, v := range c.config.Labels {
				tags[k] = v
			}

			online := 0.0
			if device.Status == "online" {
				online = 1.0
			}
			alerting := 0.0
			if device.Status == "alerting" {
				alerting = 1.0
			}

			metrics = append(metrics,
				Metric{Name: "cisco_meraki_device_online", Value: online, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
				Metric{Name: "cisco_meraki_device_alerting", Value: alerting, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			)
		}
	}

	return metrics, nil
}

// collectDNACMetrics collects metrics from DNA Center
func (c *CiscoExporter) collectDNACMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	var metrics []Metric

	// Ensure token is valid
	if err := c.ensureDNACToken(ctx); err != nil {
		return nil, err
	}

	// Collect device metrics
	if c.config.CollectDevices {
		deviceMetrics, err := c.collectDNACDevices(ctx, now)
		if err != nil {
			c.Logger().Warn("Failed to collect DNAC device metrics", zap.Error(err))
		} else {
			metrics = append(metrics, deviceMetrics...)
		}
	}

	// Collect health metrics
	if c.config.CollectHealth {
		healthMetrics, err := c.collectDNACHealth(ctx, now)
		if err != nil {
			c.Logger().Warn("Failed to collect DNAC health metrics", zap.Error(err))
		} else {
			metrics = append(metrics, healthMetrics...)
		}
	}

	return metrics, nil
}

// collectDNACDevices collects device metrics from DNA Center
func (c *CiscoExporter) collectDNACDevices(ctx context.Context, now time.Time) ([]Metric, error) {
	body, err := c.dnacRequest(ctx, "GET", "/dna/intent/api/v1/network-device", nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Response []dnacDevice `json:"response"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, device := range resp.Response {
		tags := map[string]string{
			"device_id":        device.ID,
			"hostname":         device.Hostname,
			"platform":         device.PlatformID,
			"family":           device.Family,
			"type":             device.Type,
			"role":             device.Role,
			"software_version": device.SoftwareVersion,
		}
		for k, v := range c.config.Labels {
			tags[k] = v
		}

		reachable := 0.0
		if device.ReachabilityStatus == "Reachable" {
			reachable = 1.0
		}
		managed := 0.0
		if device.CollectionStatus == "Managed" {
			managed = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "cisco_dnac_device_reachable", Value: reachable, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "cisco_dnac_device_managed", Value: managed, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// collectDNACHealth collects health metrics from DNA Center
func (c *CiscoExporter) collectDNACHealth(ctx context.Context, now time.Time) ([]Metric, error) {
	timestamp := now.Add(-5 * time.Minute).UnixMilli() // Get health from last 5 minutes
	path := fmt.Sprintf("/dna/intent/api/v1/network-health?timestamp=%d", timestamp)

	body, err := c.dnacRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Response []struct {
			HealthScore int    `json:"healthScore"`
			Category    string `json:"category"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	var metrics []Metric
	baseTags := make(map[string]string)
	for k, v := range c.config.Labels {
		baseTags[k] = v
	}

	for _, health := range resp.Response {
		tags := make(map[string]string)
		for k, v := range baseTags {
			tags[k] = v
		}
		tags["category"] = health.Category

		metrics = append(metrics,
			Metric{Name: "cisco_dnac_network_health_score", Value: float64(health.HealthScore), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// authenticateDNAC authenticates with DNA Center
func (c *CiscoExporter) authenticateDNAC(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/dna/system/api/v1/auth/token", c.config.DNACenterURL)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, nil)
	if err != nil {
		return err
	}

	req.SetBasicAuth(c.config.Username, c.config.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DNAC authentication failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Token string `json:"Token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}

	c.authToken = tokenResp.Token
	c.tokenExpiry = time.Now().Add(55 * time.Minute) // DNAC tokens expire in 1 hour

	return nil
}

// ensureDNACToken ensures we have a valid DNAC token
func (c *CiscoExporter) ensureDNACToken(ctx context.Context) error {
	if c.authToken != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}
	return c.authenticateDNAC(ctx)
}

// dnacRequest makes a request to DNA Center API
func (c *CiscoExporter) dnacRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	endpoint := c.config.DNACenterURL + path

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Auth-Token", c.authToken)
	req.Header.Set("Content-Type", "application/json")

	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DNAC API error: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return io.ReadAll(resp.Body)
}

// merakiRequest makes a request to Meraki Dashboard API
func (c *CiscoExporter) merakiRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	endpoint := c.config.MerakiBaseURL + path

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Cisco-Meraki-API-Key", c.config.MerakiAPIKey)
	req.Header.Set("Content-Type", "application/json")

	for k, v := range c.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("meraki API error: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return io.ReadAll(resp.Body)
}

// Health checks the health of Cisco connectivity
func (c *CiscoExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !c.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	switch c.config.APIType {
	case "meraki":
		_, err := c.merakiRequest(ctx, "GET", "/organizations", nil)
		if err != nil {
			return &HealthStatus{
				Healthy:   false,
				Message:   fmt.Sprintf("Meraki connection failed: %v", err),
				LastCheck: time.Now(),
				LastError: err,
				Latency:   time.Since(startTime),
			}, nil
		}
	case "dnac":
		if err := c.ensureDNACToken(ctx); err != nil {
			return &HealthStatus{
				Healthy:   false,
				Message:   fmt.Sprintf("DNAC authentication failed: %v", err),
				LastCheck: time.Now(),
				LastError: err,
				Latency:   time.Since(startTime),
			}, nil
		}
	}

	return &HealthStatus{
		Healthy:   true,
		Message:   "Cisco connected",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"api_type": c.config.APIType,
		},
	}, nil
}

// Close closes the Cisco exporter
func (c *CiscoExporter) Close(ctx context.Context) error {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	c.SetInitialized(false)
	c.Logger().Info("Cisco exporter closed")
	return nil
}
