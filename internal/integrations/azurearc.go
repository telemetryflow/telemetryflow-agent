// Package integrations provides 3rd party integration exporters.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// AzureArcConfig contains Azure Arc integration configuration
type AzureArcConfig struct {
	Enabled             bool              `mapstructure:"enabled"`
	SubscriptionID      string            `mapstructure:"subscription_id"`
	TenantID            string            `mapstructure:"tenant_id"`
	ClientID            string            `mapstructure:"client_id"`
	ClientSecret        string            `mapstructure:"client_secret"`
	ResourceGroup       string            `mapstructure:"resource_group"`
	Location            string            `mapstructure:"location"`
	MachineName         string            `mapstructure:"machine_name"`
	UseManagedIdentity  bool              `mapstructure:"use_managed_identity"`
	IMDSEndpoint        string            `mapstructure:"imds_endpoint"`
	HybridEndpoint      string            `mapstructure:"hybrid_endpoint"`
	Timeout             time.Duration     `mapstructure:"timeout"`
	ScrapeInterval      time.Duration     `mapstructure:"scrape_interval"`
	CollectMachines     bool              `mapstructure:"collect_machines"`
	CollectKubernetes   bool              `mapstructure:"collect_kubernetes"`
	CollectDataServices bool              `mapstructure:"collect_data_services"`
	CollectSQLServers   bool              `mapstructure:"collect_sql_servers"`
	Headers             map[string]string `mapstructure:"headers"`
	Labels              map[string]string `mapstructure:"labels"`
}

// AzureArcExporter exports telemetry data from Azure Arc-enabled resources
type AzureArcExporter struct {
	*BaseExporter
	config      AzureArcConfig
	httpClient  *http.Client
	accessToken string
	tokenExpiry time.Time
}

// Azure Arc resource structures
type arcConnectedMachine struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Location   string               `json:"location"`
	Type       string               `json:"type"`
	Properties arcMachineProperties `json:"properties"`
	Tags       map[string]string    `json:"tags,omitempty"`
}

type arcMachineProperties struct {
	ProvisioningState string           `json:"provisioningState"`
	Status            string           `json:"status"`
	MachineFqdn       string           `json:"machineFqdn"`
	OSName            string           `json:"osName"`
	OSVersion         string           `json:"osVersion"`
	OSType            string           `json:"osType"`
	LastStatusChange  string           `json:"lastStatusChange"`
	AgentVersion      string           `json:"agentVersion"`
	VMId              string           `json:"vmId,omitempty"`
	DisplayName       string           `json:"displayName"`
	ErrorDetails      []arcErrorDetail `json:"errorDetails,omitempty"`
	Extensions        []arcExtension   `json:"extensions,omitempty"`
}

type arcErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type arcExtension struct {
	Name              string `json:"name"`
	Type              string `json:"type"`
	ProvisioningState string `json:"provisioningState"`
}

type arcKubernetesCluster struct {
	ID         string                  `json:"id"`
	Name       string                  `json:"name"`
	Location   string                  `json:"location"`
	Type       string                  `json:"type"`
	Properties arcKubernetesProperties `json:"properties"`
	Tags       map[string]string       `json:"tags,omitempty"`
}

type arcKubernetesProperties struct {
	ProvisioningState    string `json:"provisioningState"`
	ConnectivityStatus   string `json:"connectivityStatus"`
	Distribution         string `json:"distribution"`
	Infrastructure       string `json:"infrastructure"`
	KubernetesVersion    string `json:"kubernetesVersion"`
	TotalNodeCount       int    `json:"totalNodeCount"`
	TotalCoreCount       int    `json:"totalCoreCount"`
	AgentVersion         string `json:"agentVersion"`
	LastConnectivityTime string `json:"lastConnectivityTime"`
}

type arcSQLServer struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Location   string            `json:"location"`
	Type       string            `json:"type"`
	Properties arcSQLProperties  `json:"properties"`
	Tags       map[string]string `json:"tags,omitempty"`
}

type arcSQLProperties struct {
	Version     string `json:"version"`
	Edition     string `json:"edition"`
	ContainerID string `json:"containerId"`
	Status      string `json:"status"`
	VCore       string `json:"vCore"`
	Cores       string `json:"cores"`
	LicenseType string `json:"licenseType"`
}

// NewAzureArcExporter creates a new Azure Arc exporter
func NewAzureArcExporter(config AzureArcConfig, logger *zap.Logger) *AzureArcExporter {
	return &AzureArcExporter{
		BaseExporter: NewBaseExporter(
			"azurearc",
			"hybrid",
			config.Enabled,
			logger,
			[]DataType{DataTypeMetrics},
		),
		config: config,
	}
}

// Init initializes the Azure Arc exporter
func (a *AzureArcExporter) Init(ctx context.Context) error {
	if !a.config.Enabled {
		return nil
	}

	if err := a.Validate(); err != nil {
		return err
	}

	// Set defaults
	if a.config.Location == "" {
		a.config.Location = "eastus"
	}
	if a.config.IMDSEndpoint == "" {
		a.config.IMDSEndpoint = "http://169.254.169.254"
	}
	if a.config.HybridEndpoint == "" {
		a.config.HybridEndpoint = "https://management.azure.com"
	}
	if a.config.Timeout == 0 {
		a.config.Timeout = 30 * time.Second
	}
	if a.config.ScrapeInterval == 0 {
		a.config.ScrapeInterval = 60 * time.Second
	}
	if !a.config.CollectMachines && !a.config.CollectKubernetes && !a.config.CollectSQLServers {
		// Enable all by default
		a.config.CollectMachines = true
		a.config.CollectKubernetes = true
		a.config.CollectSQLServers = true
		a.config.CollectDataServices = true
	}

	// Create HTTP client
	a.httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: a.config.Timeout,
	}

	a.SetInitialized(true)
	a.Logger().Info("Azure Arc exporter initialized",
		zap.String("subscriptionId", a.config.SubscriptionID),
		zap.String("resourceGroup", a.config.ResourceGroup),
	)

	return nil
}

// Validate validates the Azure Arc configuration
func (a *AzureArcExporter) Validate() error {
	if !a.config.Enabled {
		return nil
	}

	if a.config.SubscriptionID == "" {
		return NewValidationError("azurearc", "subscription_id", "subscription_id is required")
	}

	// Check for authentication method
	hasServicePrincipal := a.config.TenantID != "" && a.config.ClientID != "" && a.config.ClientSecret != ""

	if !hasServicePrincipal && !a.config.UseManagedIdentity {
		a.Logger().Debug("No explicit credentials provided, will use Managed Identity")
	}

	return nil
}

// Export exports telemetry data from Azure Arc
func (a *AzureArcExporter) Export(ctx context.Context, data *TelemetryData) (*ExportResult, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	// Azure Arc is primarily a pull-based system - we collect metrics from it
	metrics, err := a.CollectMetrics(ctx)
	if err != nil {
		return &ExportResult{Success: false, Error: err}, err
	}

	data.Metrics = append(data.Metrics, metrics...)

	return &ExportResult{
		Success:       true,
		ItemsExported: len(metrics),
	}, nil
}

// ExportMetrics is not applicable for Azure Arc (it's a data source)
func (a *AzureArcExporter) ExportMetrics(ctx context.Context, metrics []Metric) (*ExportResult, error) {
	return nil, fmt.Errorf("azure arc is a data source, not a metrics destination")
}

// ExportTraces is not supported by Azure Arc
func (a *AzureArcExporter) ExportTraces(ctx context.Context, traces []Trace) (*ExportResult, error) {
	return nil, fmt.Errorf("azure arc does not support traces")
}

// ExportLogs is not supported by Azure Arc
func (a *AzureArcExporter) ExportLogs(ctx context.Context, logs []LogEntry) (*ExportResult, error) {
	return nil, fmt.Errorf("azure arc does not support log ingestion")
}

// CollectMetrics collects metrics from Azure Arc-enabled resources
func (a *AzureArcExporter) CollectMetrics(ctx context.Context) ([]Metric, error) {
	if !a.config.Enabled {
		return nil, ErrNotEnabled
	}

	if !a.IsInitialized() {
		return nil, ErrNotInitialized
	}

	// Ensure we have a valid token
	if err := a.ensureToken(ctx); err != nil {
		return nil, err
	}

	var metrics []Metric
	now := time.Now()

	// Collect connected machine metrics
	if a.config.CollectMachines {
		machineMetrics, err := a.collectMachineMetrics(ctx, now)
		if err != nil {
			a.Logger().Warn("Failed to collect machine metrics", zap.Error(err))
		} else {
			metrics = append(metrics, machineMetrics...)
		}
	}

	// Collect Kubernetes cluster metrics
	if a.config.CollectKubernetes {
		k8sMetrics, err := a.collectKubernetesMetrics(ctx, now)
		if err != nil {
			a.Logger().Warn("Failed to collect Kubernetes metrics", zap.Error(err))
		} else {
			metrics = append(metrics, k8sMetrics...)
		}
	}

	// Collect SQL Server metrics
	if a.config.CollectSQLServers {
		sqlMetrics, err := a.collectSQLServerMetrics(ctx, now)
		if err != nil {
			a.Logger().Warn("Failed to collect SQL Server metrics", zap.Error(err))
		} else {
			metrics = append(metrics, sqlMetrics...)
		}
	}

	return metrics, nil
}

// collectMachineMetrics collects metrics from Arc-enabled machines
func (a *AzureArcExporter) collectMachineMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	machines, err := a.listConnectedMachines(ctx)
	if err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, machine := range machines {
		tags := map[string]string{
			"resource_id":   machine.ID,
			"machine_name":  machine.Name,
			"location":      machine.Location,
			"os_type":       machine.Properties.OSType,
			"os_name":       machine.Properties.OSName,
			"os_version":    machine.Properties.OSVersion,
			"agent_version": machine.Properties.AgentVersion,
			"status":        machine.Properties.Status,
		}
		for k, v := range a.config.Labels {
			tags[k] = v
		}
		for k, v := range machine.Tags {
			tags["tag_"+k] = v
		}

		// Status metric
		connected := 0.0
		if machine.Properties.Status == "Connected" {
			connected = 1.0
		}

		// Extension count
		extensionCount := len(machine.Properties.Extensions)
		healthyExtensions := 0
		for _, ext := range machine.Properties.Extensions {
			if ext.ProvisioningState == "Succeeded" {
				healthyExtensions++
			}
		}

		metrics = append(metrics,
			Metric{Name: "azurearc_machine_connected", Value: connected, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "azurearc_machine_extension_count", Value: float64(extensionCount), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "azurearc_machine_healthy_extensions", Value: float64(healthyExtensions), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "azurearc_machine_error_count", Value: float64(len(machine.Properties.ErrorDetails)), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// collectKubernetesMetrics collects metrics from Arc-enabled Kubernetes clusters
func (a *AzureArcExporter) collectKubernetesMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	clusters, err := a.listKubernetesClusters(ctx)
	if err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, cluster := range clusters {
		tags := map[string]string{
			"resource_id":         cluster.ID,
			"cluster_name":        cluster.Name,
			"location":            cluster.Location,
			"distribution":        cluster.Properties.Distribution,
			"infrastructure":      cluster.Properties.Infrastructure,
			"kubernetes_version":  cluster.Properties.KubernetesVersion,
			"agent_version":       cluster.Properties.AgentVersion,
			"connectivity_status": cluster.Properties.ConnectivityStatus,
		}
		for k, v := range a.config.Labels {
			tags[k] = v
		}
		for k, v := range cluster.Tags {
			tags["tag_"+k] = v
		}

		// Connectivity status metric
		connected := 0.0
		if cluster.Properties.ConnectivityStatus == "Connected" {
			connected = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "azurearc_kubernetes_connected", Value: connected, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "azurearc_kubernetes_node_count", Value: float64(cluster.Properties.TotalNodeCount), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
			Metric{Name: "azurearc_kubernetes_core_count", Value: float64(cluster.Properties.TotalCoreCount), Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// collectSQLServerMetrics collects metrics from Arc-enabled SQL servers
func (a *AzureArcExporter) collectSQLServerMetrics(ctx context.Context, now time.Time) ([]Metric, error) {
	servers, err := a.listSQLServers(ctx)
	if err != nil {
		return nil, err
	}

	var metrics []Metric
	for _, server := range servers {
		tags := map[string]string{
			"resource_id":  server.ID,
			"server_name":  server.Name,
			"location":     server.Location,
			"version":      server.Properties.Version,
			"edition":      server.Properties.Edition,
			"license_type": server.Properties.LicenseType,
			"status":       server.Properties.Status,
		}
		for k, v := range a.config.Labels {
			tags[k] = v
		}
		for k, v := range server.Tags {
			tags["tag_"+k] = v
		}

		// Status metric
		running := 0.0
		if server.Properties.Status == "Registered" || server.Properties.Status == "Connected" {
			running = 1.0
		}

		metrics = append(metrics,
			Metric{Name: "azurearc_sqlserver_running", Value: running, Type: MetricTypeGauge, Timestamp: now, Tags: tags},
		)
	}

	return metrics, nil
}

// listConnectedMachines lists all Arc-enabled machines
func (a *AzureArcExporter) listConnectedMachines(ctx context.Context) ([]arcConnectedMachine, error) {
	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.HybridCompute/machines?api-version=2022-12-27",
		a.config.SubscriptionID)
	if a.config.ResourceGroup != "" {
		path = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.HybridCompute/machines?api-version=2022-12-27",
			a.config.SubscriptionID, a.config.ResourceGroup)
	}

	body, err := a.apiRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Value []arcConnectedMachine `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return response.Value, nil
}

// listKubernetesClusters lists all Arc-enabled Kubernetes clusters
func (a *AzureArcExporter) listKubernetesClusters(ctx context.Context) ([]arcKubernetesCluster, error) {
	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Kubernetes/connectedClusters?api-version=2022-10-01-preview",
		a.config.SubscriptionID)
	if a.config.ResourceGroup != "" {
		path = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Kubernetes/connectedClusters?api-version=2022-10-01-preview",
			a.config.SubscriptionID, a.config.ResourceGroup)
	}

	body, err := a.apiRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Value []arcKubernetesCluster `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return response.Value, nil
}

// listSQLServers lists all Arc-enabled SQL servers
func (a *AzureArcExporter) listSQLServers(ctx context.Context) ([]arcSQLServer, error) {
	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.AzureArcData/sqlServerInstances?api-version=2022-03-01-preview",
		a.config.SubscriptionID)
	if a.config.ResourceGroup != "" {
		path = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.AzureArcData/sqlServerInstances?api-version=2022-03-01-preview",
			a.config.SubscriptionID, a.config.ResourceGroup)
	}

	body, err := a.apiRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var response struct {
		Value []arcSQLServer `json:"value"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return response.Value, nil
}

// ensureToken ensures we have a valid access token
func (a *AzureArcExporter) ensureToken(ctx context.Context) error {
	if a.accessToken != "" && time.Now().Before(a.tokenExpiry) {
		return nil
	}

	if a.config.UseManagedIdentity {
		return a.getManagedIdentityToken(ctx)
	}

	return a.getServicePrincipalToken(ctx)
}

// getManagedIdentityToken gets a token using managed identity
func (a *AzureArcExporter) getManagedIdentityToken(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
		a.config.IMDSEndpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Metadata", "true")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get managed identity token: status=%d body=%s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   string `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}

	a.accessToken = tokenResp.AccessToken
	a.tokenExpiry = time.Now().Add(50 * time.Minute) // Conservative expiry

	return nil
}

// getServicePrincipalToken gets a token using service principal credentials
func (a *AzureArcExporter) getServicePrincipalToken(ctx context.Context) error {
	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", a.config.TenantID)

	data := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&scope=https://management.azure.com/.default",
		a.config.ClientID, a.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBufferString(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get service principal token: status=%d body=%s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}

	a.accessToken = tokenResp.AccessToken
	a.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

	return nil
}

// apiRequest makes an authenticated request to Azure ARM API
func (a *AzureArcExporter) apiRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	endpoint := a.config.HybridEndpoint + path

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+a.accessToken)
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for k, v := range a.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("azure arc API error: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return io.ReadAll(resp.Body)
}

// Health checks the health of Azure Arc connectivity
func (a *AzureArcExporter) Health(ctx context.Context) (*HealthStatus, error) {
	if !a.config.Enabled {
		return &HealthStatus{Healthy: false, Message: "integration disabled"}, nil
	}

	startTime := time.Now()

	// Ensure we have a valid token
	if err := a.ensureToken(ctx); err != nil {
		return &HealthStatus{
			Healthy:   false,
			Message:   fmt.Sprintf("authentication failed: %v", err),
			LastCheck: time.Now(),
			LastError: err,
			Latency:   time.Since(startTime),
		}, nil
	}

	// Try to list machines as health check
	_, err := a.listConnectedMachines(ctx)
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
		Message:   "Azure Arc connected",
		LastCheck: time.Now(),
		Latency:   time.Since(startTime),
		Details: map[string]interface{}{
			"subscription_id": a.config.SubscriptionID,
			"resource_group":  a.config.ResourceGroup,
		},
	}, nil
}

// Close closes the Azure Arc exporter
func (a *AzureArcExporter) Close(ctx context.Context) error {
	if a.httpClient != nil {
		a.httpClient.CloseIdleConnections()
	}
	a.SetInitialized(false)
	a.Logger().Info("Azure Arc exporter closed")
	return nil
}
