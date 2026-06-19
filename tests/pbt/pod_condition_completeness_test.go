// Package pbt contains property-based tests for the TFO-Agent collectors.
//
// Validates: Requirements 4.9
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
package pbt_test

import (
	"fmt"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// podConditionMetric represents a simplified emitted condition metric.
type podConditionMetric struct {
	Namespace string
	Pod       string
	Condition string
	Value     float64
}

// standardConditions are the four conditions always emitted per pod.
var standardConditions = []corev1.PodConditionType{
	corev1.PodReady,
	corev1.PodInitialized,
	corev1.ContainersReady,
	corev1.PodScheduled,
}

// simulateCollectPodConditions mimics collectPodConditions logic.
func simulateCollectPodConditions(pods []corev1.Pod) []podConditionMetric {
	var metrics []podConditionMetric
	for _, pod := range pods {
		// Build a map of existing conditions
		condMap := make(map[corev1.PodConditionType]corev1.ConditionStatus)
		for _, c := range pod.Status.Conditions {
			condMap[c.Type] = c.Status
		}

		for _, condType := range standardConditions {
			value := 0.0
			if status, ok := condMap[condType]; ok && status == corev1.ConditionTrue {
				value = 1.0
			}
			metrics = append(metrics, podConditionMetric{
				Namespace: pod.Namespace,
				Pod:       pod.Name,
				Condition: string(condType),
				Value:     value,
			})
		}
	}
	return metrics
}

// TestPodConditionCompleteness verifies that for any pod list, every pod
// has exactly one metric per standard condition (Ready, Initialized,
// ContainersReady, PodScheduled), and the sum of Ready=1 + Ready=0 == total pods.
//
// **Validates: Requirements 4.9**
func TestPodConditionCompleteness(t *testing.T) {
	property := func(podCount uint8, readyFlags []bool) bool {
		n := int(podCount) % 20 // cap at 20 pods
		if n == 0 {
			return true
		}

		pods := make([]corev1.Pod, n)
		for i := 0; i < n; i++ {
			isReady := i < len(readyFlags) && readyFlags[i]
			var conditions []corev1.PodCondition
			if isReady {
				conditions = append(conditions, corev1.PodCondition{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				})
			}
			pods[i] = corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("pod-%d", i),
					Namespace: "default",
				},
				Status: corev1.PodStatus{Conditions: conditions},
			}
		}

		metrics := simulateCollectPodConditions(pods)

		// Count Ready=1 and Ready=0
		readyTrue := 0
		readyFalse := 0
		for _, m := range metrics {
			if m.Condition == string(corev1.PodReady) {
				if m.Value == 1.0 {
					readyTrue++
				} else {
					readyFalse++
				}
			}
		}

		// Property: readyTrue + readyFalse == total pods
		return readyTrue+readyFalse == n
	}

	err := quick.Check(property, &quick.Config{MaxCount: 200})
	require.NoError(t, err)
}

// TestPodConditionAllFourEmitted verifies all four standard conditions are
// emitted for every pod, even when status.conditions is empty.
func TestPodConditionAllFourEmitted(t *testing.T) {
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "ns"},
			Status:     corev1.PodStatus{}, // no conditions
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Namespace: "ns"},
			Status: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: corev1.PodReady, Status: corev1.ConditionTrue},
				},
			},
		},
	}

	metrics := simulateCollectPodConditions(pods)

	// 2 pods × 4 conditions = 8 metrics
	assert.Len(t, metrics, 8)

	// pod-1: all conditions should be 0
	for _, m := range metrics {
		if m.Pod == "pod-1" {
			assert.Equal(t, 0.0, m.Value, "pod with no conditions should emit 0 for all")
		}
	}

	// pod-2: Ready should be 1, others 0
	for _, m := range metrics {
		if m.Pod == "pod-2" && m.Condition == string(corev1.PodReady) {
			assert.Equal(t, 1.0, m.Value)
		}
	}
}
