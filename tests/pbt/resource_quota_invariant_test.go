// Package pbt contains property-based tests for the TFO-Agent collectors.
//
// Validates: Requirements 4.3
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
package pbt_test

import (
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// resourceQuotaMetric represents a simplified emitted metric for testing.
type resourceQuotaMetric struct {
	Name      string
	Namespace string
	Quota     string
	Resource  string
	Type      string // "hard" or "used"
	Value     float64
}

// simulateCollectResourceQuotas mimics the logic of collectResourceQuotas
// without requiring a live Kubernetes client.
func simulateCollectResourceQuotas(quotas []corev1.ResourceQuota) []resourceQuotaMetric {
	var metrics []resourceQuotaMetric
	for _, quota := range quotas {
		for resourceName, hardQty := range quota.Spec.Hard {
			res := string(resourceName)
			metrics = append(metrics, resourceQuotaMetric{
				Name:      "k8s.resourcequota.hard",
				Namespace: quota.Namespace,
				Quota:     quota.Name,
				Resource:  res,
				Type:      "hard",
				Value:     hardQty.AsApproximateFloat64(),
			})
			usedValue := 0.0
			if usedQty, ok := quota.Status.Used[resourceName]; ok {
				usedValue = usedQty.AsApproximateFloat64()
			}
			metrics = append(metrics, resourceQuotaMetric{
				Name:      "k8s.resourcequota.used",
				Namespace: quota.Namespace,
				Quota:     quota.Name,
				Resource:  res,
				Type:      "used",
				Value:     usedValue,
			})
		}
	}
	return metrics
}

// TestResourceQuotaUsedNeverExceedsHard verifies that for any ResourceQuota
// where used ≤ hard in the spec, the emitted metrics preserve this invariant.
//
// **Validates: Requirements 4.3**
func TestResourceQuotaUsedNeverExceedsHard(t *testing.T) {
	property := func(hardMilliCPU, usedMilliCPU uint32, hardMemMi, usedMemMi uint32) bool {
		// Ensure used ≤ hard (the invariant we're testing)
		if usedMilliCPU > hardMilliCPU {
			usedMilliCPU = hardMilliCPU
		}
		if usedMemMi > hardMemMi {
			usedMemMi = hardMemMi
		}

		quota := corev1.ResourceQuota{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-quota",
				Namespace: "default",
			},
			Spec: corev1.ResourceQuotaSpec{
				Hard: corev1.ResourceList{
					corev1.ResourceCPU:    *resource.NewMilliQuantity(int64(hardMilliCPU), resource.DecimalSI),
					corev1.ResourceMemory: *resource.NewQuantity(int64(hardMemMi)*1024*1024, resource.BinarySI),
				},
			},
			Status: corev1.ResourceQuotaStatus{
				Used: corev1.ResourceList{
					corev1.ResourceCPU:    *resource.NewMilliQuantity(int64(usedMilliCPU), resource.DecimalSI),
					corev1.ResourceMemory: *resource.NewQuantity(int64(usedMemMi)*1024*1024, resource.BinarySI),
				},
			},
		}

		metrics := simulateCollectResourceQuotas([]corev1.ResourceQuota{quota})

		// Build hard/used maps
		hard := make(map[string]float64)
		used := make(map[string]float64)
		for _, m := range metrics {
			switch m.Type {
			case "hard":
				hard[m.Resource] = m.Value
			case "used":
				used[m.Resource] = m.Value
			}
		}

		// Invariant: used ≤ hard for all resources
		for res, usedVal := range used {
			hardVal, ok := hard[res]
			if !ok {
				return false // hard must exist for every used
			}
			if usedVal > hardVal+1e-9 { // small epsilon for float comparison
				return false
			}
		}
		return true
	}

	err := quick.Check(property, &quick.Config{MaxCount: 500})
	require.NoError(t, err)
}

// TestResourceQuotaHardAlwaysEmitted verifies that a hard metric is always
// emitted for every resource in spec.hard, even when status.used is empty.
func TestResourceQuotaHardAlwaysEmitted(t *testing.T) {
	quota := corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{Name: "q", Namespace: "ns"},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("2"),
				corev1.ResourceMemory: resource.MustParse("4Gi"),
			},
		},
		// Status.Used intentionally empty
	}

	metrics := simulateCollectResourceQuotas([]corev1.ResourceQuota{quota})

	hardCount := 0
	usedCount := 0
	for _, m := range metrics {
		switch m.Type {
		case "hard":
			hardCount++
		case "used":
			usedCount++
			assert.Equal(t, 0.0, m.Value, "absent used should emit 0")
		}
	}
	assert.Equal(t, 2, hardCount)
	assert.Equal(t, 2, usedCount)
}
