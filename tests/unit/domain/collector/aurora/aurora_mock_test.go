// Package aurora_test contains unit tests for the Aurora collector module.
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

package aurora_test

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	smithycbor "github.com/aws/smithy-go/encoding/cbor"

	"github.com/telemetryflow/telemetryflow-agent/internal/config"
)

// mockMode controls the behaviour of the fake AWS endpoint.
type mockMode int

const (
	mockSuccess    mockMode = iota // return well-formed data
	mockError                      // return a non-throttling error (HTTP 400)
	mockThrottling                 // return a throttling error (HTTP 400 + Throttling)
)

// newMockAWSServer starts an httptest server that emulates the RDS, CloudWatch
// and Performance Insights endpoints used by the Aurora collector.
func newMockAWSServer(t *testing.T, mode mockMode) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)
		target := r.Header.Get("X-Amz-Target")

		if mode == mockThrottling {
			writeThrottle(w, r, target)
			return
		}
		if mode == mockError {
			w.WriteHeader(http.StatusBadRequest)
			if strings.Contains(target, "PerformanceInsights") {
				_, _ = w.Write([]byte(`{"__type":"InternalServiceError","message":"boom"}`))
			} else {
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InternalFailure</Code><Message>boom</Message></Error></ErrorResponse>`))
			}
			return
		}

		// Success mode.
		writeSuccess(w, r, target, body, bodyBytes, false)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeThrottle writes an error whose message matches the collector's
// isThrottlingError check ("Rate exceeded") but whose error code is NOT one the
// AWS SDK auto-retries. This forces the collector's own backoff/retry loop to
// run instead of the SDK transparently retrying.
func writeThrottle(w http.ResponseWriter, r *http.Request, target string) {
	// CloudWatch uses rpc-v2-cbor; errors must be CBOR-encoded.
	if r != nil && strings.Contains(r.URL.Path, "GetMetricData") {
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("smithy-protocol", "rpc-v2-cbor")
		w.Header().Set("X-Amzn-Errortype", "ValidationException")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(smithycbor.Encode(smithycbor.Map{
			"__type":  smithycbor.String("ValidationException"),
			"Message": smithycbor.String("Rate exceeded"),
			"message": smithycbor.String("Rate exceeded"),
		}))
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	if strings.Contains(target, "PerformanceInsights") {
		_, _ = w.Write([]byte(`{"__type":"ValidationException","message":"Rate exceeded"}`))
	} else {
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>ValidationError</Code><Message>Rate exceeded</Message></Error></ErrorResponse>`))
	}
}

// writeSuccess writes a well-formed response for RDS/CloudWatch/PI. When
// multiStmt is true the PI SQL response carries multiple statement digests.
func writeSuccess(w http.ResponseWriter, r *http.Request, target, body string, bodyBytes []byte, multiStmt bool) {
	if strings.Contains(target, "GetResourceMetrics") {
		writePIResponse(w, bodyBytes, multiStmt)
		return
	}
	// CloudWatch uses the smithy rpc-v2-cbor protocol (path-based routing).
	if strings.Contains(r.URL.Path, "GetMetricData") {
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("smithy-protocol", "rpc-v2-cbor")
		_, _ = w.Write(getMetricDataCBOR())
		return
	}
	switch {
	case strings.Contains(body, "Action=DescribeDBClusters"):
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(describeDBClustersXML))
	case strings.Contains(body, "Action=DescribeDBInstances"):
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(describeDBInstancesXML))
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InvalidAction</Code></Error></ErrorResponse>`))
	}
}

// newThrottleThenOKServer throttles the first failN requests and then serves
// well-formed responses. Used to exercise the retry/backoff continue branch.
func newThrottleThenOKServer(t *testing.T, failN int32, multiStmt bool) *httptest.Server {
	t.Helper()
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)
		target := r.Header.Get("X-Amz-Target")
		n := atomic.AddInt32(&count, 1)
		if n <= failN {
			writeThrottle(w, r, target)
			return
		}
		writeSuccess(w, r, target, body, bodyBytes, multiStmt)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newMultiStmtServer serves success responses with multiple SQL digests for QAN.
func newMultiStmtServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)
		target := r.Header.Get("X-Amz-Target")
		writeSuccess(w, r, target, body, bodyBytes, true)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newEmptyClusterServer returns a server whose DescribeDBClusters response has
// no clusters, to exercise the "cluster not found" path.
func newEmptyClusterServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<DescribeDBClustersResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/">` +
			`<DescribeDBClustersResult><DBClusters></DBClusters></DescribeDBClustersResult>` +
			`</DescribeDBClustersResponse>`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writePIResponse crafts a PI GetResourceMetrics JSON body keyed off the
// requested metric so that both plain metrics and SQL-digest metrics are
// exercised.
func writePIResponse(w http.ResponseWriter, reqBody []byte, multiStmt bool) {
	var req struct {
		MetricQueries []struct {
			Metric string `json:"Metric"`
		} `json:"MetricQueries"`
	}
	_ = json.Unmarshal(reqBody, &req)
	metric := "db.load.avg"
	if len(req.MetricQueries) > 0 {
		metric = req.MetricQueries[0].Metric
	}

	value := 3.5
	if strings.Contains(metric, "executions") {
		value = 10
	} else if strings.Contains(metric, "avg_latency") {
		value = 5 // ms
	}

	isSQL := strings.HasPrefix(metric, "db.sql") || strings.HasPrefix(metric, "db.wait_event")

	var metricList []map[string]any
	if isSQL {
		statements := []string{"SELECT * FROM orders WHERE id = ?"}
		if multiStmt {
			// A very long statement to exercise the example-truncation branch,
			// plus a second digest so ranking/limit logic runs.
			statements = []string{
				strings.Repeat("A", 2500),
				"SELECT * FROM users WHERE tenant = ?",
			}
		}
		for i, stmt := range statements {
			metricList = append(metricList, map[string]any{
				"Key": map[string]any{
					"Metric": metric,
					"Dimensions": map[string]string{
						"db.sql.statement": stmt,
						"db.sql.id":        fmt.Sprintf("digest-%d", i),
					},
				},
				"DataPoints": []map[string]any{{"Timestamp": 1704067200.0, "Value": value}},
			})
		}
	} else {
		metricList = []map[string]any{
			{
				"Key":        map[string]any{"Metric": metric},
				"DataPoints": []map[string]any{{"Timestamp": 1704067200.0, "Value": value}},
			},
		}
	}

	resp := map[string]any{
		"AlignedStartTime": 1.0,
		"AlignedEndTime":   2.0,
		"Identifier":       "arn:aws:rds:us-east-1:123456789012:db:inst-writer",
		"MetricList":       metricList,
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(resp)
}

// getMetricDataCBOR builds a CBOR-encoded GetMetricData response for the
// smithy rpc-v2-cbor protocol used by CloudWatch.
func getMetricDataCBOR() []byte {
	ts := &smithycbor.Tag{ID: 1, Value: smithycbor.Float64(1704067200)}
	result := func(id, label string, val float64) smithycbor.Map {
		return smithycbor.Map{
			"Id":         smithycbor.String(id),
			"Label":      smithycbor.String(label),
			"StatusCode": smithycbor.String("Complete"),
			"Timestamps": smithycbor.List{ts},
			"Values":     smithycbor.List{smithycbor.Float64(val)},
		}
	}
	root := smithycbor.Map{
		"MetricDataResults": smithycbor.List{
			result("m_0", "CPUUtilization", 42.5),
			result("m_1", "DatabaseConnections", 17),
			// A NaN value exercises the collector's NaN/Inf skip branch.
			result("m_2", "FreeableMemory", math.NaN()),
		},
	}
	return smithycbor.Encode(root)
}

const describeDBClustersXML = `<DescribeDBClustersResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/">
  <DescribeDBClustersResult>
    <DBClusters>
      <DBCluster>
        <DBClusterIdentifier>test-cluster</DBClusterIdentifier>
        <DBClusterArn>arn:aws:rds:us-east-1:123456789012:cluster:test-cluster</DBClusterArn>
        <Engine>aurora-postgresql</Engine>
        <EngineVersion>15.3</EngineVersion>
        <EngineMode>provisioned</EngineMode>
        <DatabaseName>appdb</DatabaseName>
        <Port>5432</Port>
        <MultiAZ>true</MultiAZ>
        <Status>available</Status>
        <StorageEncrypted>true</StorageEncrypted>
        <GlobalClusterIdentifier>global-1</GlobalClusterIdentifier>
        <DBClusterMembers>
          <DBClusterMember>
            <DBInstanceIdentifier>inst-writer</DBInstanceIdentifier>
            <IsClusterWriter>true</IsClusterWriter>
          </DBClusterMember>
          <DBClusterMember>
            <DBInstanceIdentifier>inst-reader</DBInstanceIdentifier>
            <IsClusterWriter>false</IsClusterWriter>
          </DBClusterMember>
        </DBClusterMembers>
      </DBCluster>
    </DBClusters>
  </DescribeDBClustersResult>
</DescribeDBClustersResponse>`

const describeDBInstancesXML = `<DescribeDBInstancesResponse xmlns="http://rds.amazonaws.com/doc/2014-10-31/">
  <DescribeDBInstancesResult>
    <DBInstances>
      <DBInstance>
        <DBInstanceIdentifier>inst-writer</DBInstanceIdentifier>
        <DBInstanceArn>arn:aws:rds:us-east-1:123456789012:db:inst-writer</DBInstanceArn>
        <DBInstanceClass>db.r6g.large</DBInstanceClass>
        <AvailabilityZone>us-east-1a</AvailabilityZone>
        <DBInstanceStatus>available</DBInstanceStatus>
        <PerformanceInsightsEnabled>true</PerformanceInsightsEnabled>
        <Engine>aurora-postgresql</Engine>
        <EngineVersion>15.3</EngineVersion>
        <Endpoint>
          <Address>inst-writer.cluster-abc.us-east-1.rds.amazonaws.com</Address>
          <Port>5432</Port>
        </Endpoint>
      </DBInstance>
      <DBInstance>
        <DBInstanceIdentifier>inst-reader</DBInstanceIdentifier>
        <DBInstanceArn>arn:aws:rds:us-east-1:123456789012:db:inst-reader</DBInstanceArn>
        <DBInstanceClass>db.r6g.large</DBInstanceClass>
        <AvailabilityZone>us-east-1b</AvailabilityZone>
        <DBInstanceStatus>available</DBInstanceStatus>
        <PerformanceInsightsEnabled>false</PerformanceInsightsEnabled>
        <Engine>aurora-postgresql</Engine>
        <EngineVersion>15.3</EngineVersion>
      </DBInstance>
    </DBInstances>
  </DescribeDBInstancesResult>
</DescribeDBInstancesResponse>`

// setAWSTestEnv points the AWS SDK at the mock server via the global endpoint
// override and supplies static credentials.
func setAWSTestEnv(t *testing.T, endpoint string) {
	t.Helper()
	t.Setenv("AWS_ENDPOINT_URL", endpoint)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	// Isolate from any developer-machine shared AWS config/credentials so that
	// LoadDefaultConfig does not fail on profile parsing.
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_SDK_LOAD_CONFIG", "0")
}

// setBadAWSConfig isolates from machine config and forces LoadDefaultConfig to
// fail by pointing AWS_CA_BUNDLE at a nonexistent file.
func setBadAWSConfig(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CA_BUNDLE", "/nonexistent/telemetryflow-aurora-ca.pem")
}

// baseCollectorConfig returns a minimal Aurora collector config with a single cluster.
func baseCollectorConfig() config.AuroraCollectorConfig {
	return config.AuroraCollectorConfig{
		Enabled:  true,
		EnablePI: true,
		Clusters: []config.AuroraClusterConfig{
			{
				ClusterID:       "test-cluster",
				Region:          "us-east-1",
				AccessKeyID:     "AKIA",
				SecretAccessKey: "secret",
				Tags:            map[string]string{"team": "platform"},
			},
		},
	}
}
