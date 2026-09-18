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
package kubernetes

import (
	"context"
	"encoding/json"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// vpaGVR is the GroupVersionResource for autoscaling.k8s.io/v1 VerticalPodAutoscaler.
var vpaGVR = schema.GroupVersionResource{
	Group:    "autoscaling.k8s.io",
	Version:  "v1",
	Resource: "verticalpodautoscalers",
}

// vpaGroupVersion is the API group/version string checked via discovery.
const vpaGroupVersion = "autoscaling.k8s.io/v1"

// isVPACRDAbsent returns true when the error signals the VPA CRD is not
// installed on this cluster (NotFound or no-match for the API group).
func isVPACRDAbsent(err error) bool {
	if err == nil {
		return false
	}
	return apierrors.IsNotFound(err) || meta.IsNoMatchError(err)
}

// vpaRaw mirrors the fields of autoscaling.k8s.io/v1 VerticalPodAutoscaler
// that we care about.  Using an inline struct avoids importing the external
// VPA client library while keeping the dynamic-client path simple.
type vpaRaw struct {
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels,omitempty"`
	} `json:"metadata"`
	Spec struct {
		TargetRef *struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"targetRef"`
		UpdatePolicy *struct {
			UpdateMode *string `json:"updateMode"`
		} `json:"updatePolicy"`
	} `json:"spec"`
	Status struct {
		Recommendation *struct {
			ContainerRecommendations []vpaContainerRec `json:"containerRecommendations"`
		} `json:"recommendation"`
	} `json:"status"`
}

type vpaContainerRec struct {
	ContainerName string                 `json:"containerName"`
	Target        map[string]interface{} `json:"target"`
	LowerBound    map[string]interface{} `json:"lowerBound"`
	UpperBound    map[string]interface{} `json:"upperBound"`
}

// collectVPAs collects VerticalPodAutoscaler resources via the dynamic client.
//
// Graceful NO-OP: if the VPA CRD (autoscaling.k8s.io/v1 VerticalPodAutoscaler)
// is absent from the cluster, the function returns empty slices and no error so
// the collect loop continues uninterrupted. It emits a single debug log per
// call rather than repeating an error for every cycle, preventing log spam on
// clusters (like the TDID demo) that do not run a VPA controller.
func collectVPAs(
	ctx context.Context,
	cs kubernetes.Interface,
	dc dynamic.Interface,
	cfg Config,
	cluster string,
	logger *zap.Logger,
) ([]collector.Metric, []VPAState, error) {
	// Fast CRD presence check: query discovery before issuing a list request.
	// This avoids a 404 round-trip on every collect cycle for clusters without VPA.
	_, err := cs.Discovery().ServerResourcesForGroupVersion(vpaGroupVersion)
	if err != nil {
		if isVPACRDAbsent(err) {
			logger.Debug("vpa: autoscaling.k8s.io/v1 CRD absent, skipping VPA collection")
			return nil, nil, nil
		}
		// Discovery error (transient network issue etc.) — log and skip this cycle.
		logger.Warn("vpa: discovery check failed, skipping VPA collection", zap.Error(err))
		return nil, nil, nil
	}

	if dc == nil {
		logger.Debug("vpa: dynamic client unavailable, skipping VPA collection")
		return nil, nil, nil
	}

	rawList, err := dc.Resource(vpaGVR).Namespace("").List(ctx, metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
	})
	if err != nil {
		if isVPACRDAbsent(err) {
			logger.Debug("vpa: VPA CRD absent on list, skipping", zap.Error(err))
			return nil, nil, nil
		}
		return nil, nil, err
	}

	var metrics []collector.Metric
	var states []VPAState

	for i := range rawList.Items {
		item := &rawList.Items[i]

		// Re-marshal via JSON to decode into our typed struct.
		b, merr := item.MarshalJSON()
		if merr != nil {
			logger.Debug("vpa: marshal failed", zap.Error(merr))
			continue
		}
		var vpa vpaRaw
		if merr = json.Unmarshal(b, &vpa); merr != nil {
			logger.Debug("vpa: unmarshal failed", zap.Error(merr))
			continue
		}

		ns := vpa.Metadata.Namespace
		name := vpa.Metadata.Name

		if !cfg.shouldCollectNamespace(ns) {
			continue
		}

		updateMode := ""
		if vpa.Spec.UpdatePolicy != nil && vpa.Spec.UpdatePolicy.UpdateMode != nil {
			updateMode = *vpa.Spec.UpdatePolicy.UpdateMode
		}

		targetKind, targetName := "", ""
		if vpa.Spec.TargetRef != nil {
			targetKind = vpa.Spec.TargetRef.Kind
			targetName = vpa.Spec.TargetRef.Name
		}

		baseLabels := map[string]string{
			"cluster":     cluster,
			"namespace":   ns,
			"vpa":         name,
			"target_kind": targetKind,
			"target_name": targetName,
			"update_mode": updateMode,
		}

		// Emit an info gauge (always 1) per VPA so the platform has a time-series
		// of VPA existence with update mode as a label.
		metrics = append(metrics,
			collector.NewMetric("k8s.vpa.info", 1.0, collector.MetricTypeGauge).
				WithLabels(baseLabels).
				WithDescription("VPA info (labels carry update mode and target)"),
		)

		var containerRecs []VPAContainerRecommendation

		if vpa.Status.Recommendation != nil {
			for _, rec := range vpa.Status.Recommendation.ContainerRecommendations {
				cLabels := map[string]string{
					"cluster":    cluster,
					"namespace":  ns,
					"vpa":        name,
					"container":  rec.ContainerName,
					"target_ref": targetKind + "/" + targetName,
				}

				// Helper: extract milli-CPU (m) or memory (bytes) from a resource map.
				emitResourceRec := func(bounds map[string]interface{}, bound string) {
					if v, ok := extractQuantityFromMap(bounds, "cpu"); ok {
						metrics = append(metrics,
							collector.NewMetric("k8s.vpa.recommendation.cpu", v, collector.MetricTypeGauge).
								WithLabels(cLabels).
								WithLabel("bound", bound).
								WithDescription("VPA CPU recommendation in milli-cores"),
						)
					}
					if v, ok := extractQuantityFromMap(bounds, "memory"); ok {
						metrics = append(metrics,
							collector.NewMetric("k8s.vpa.recommendation.memory", v, collector.MetricTypeGauge).
								WithLabels(cLabels).
								WithLabel("bound", bound).
								WithDescription("VPA memory recommendation in bytes"),
						)
					}
				}

				emitResourceRec(rec.Target, "target")
				emitResourceRec(rec.LowerBound, "lower")
				emitResourceRec(rec.UpperBound, "upper")

				containerRecs = append(containerRecs, VPAContainerRecommendation{
					ContainerName: rec.ContainerName,
					TargetCPU:     extractQuantityStringFromMap(rec.Target, "cpu"),
					TargetMemory:  extractQuantityStringFromMap(rec.Target, "memory"),
					LowerCPU:      extractQuantityStringFromMap(rec.LowerBound, "cpu"),
					LowerMemory:   extractQuantityStringFromMap(rec.LowerBound, "memory"),
					UpperCPU:      extractQuantityStringFromMap(rec.UpperBound, "cpu"),
					UpperMemory:   extractQuantityStringFromMap(rec.UpperBound, "memory"),
				})
			}
		}

		states = append(states, VPAState{
			Name:            name,
			Namespace:       ns,
			ScaleTargetKind: targetKind,
			ScaleTargetName: targetName,
			UpdateMode:      updateMode,
			Recommendations: containerRecs,
			Labels:          vpa.Metadata.Labels,
		})
	}

	return metrics, states, nil
}

// extractQuantityFromMap returns (value, true) if key exists in m and can be
// parsed as a Kubernetes quantity string.
func extractQuantityFromMap(m map[string]interface{}, key string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	return parseQuantityString(s), true
}

// extractQuantityStringFromMap returns the raw string value for key in m, or "".
func extractQuantityStringFromMap(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
