// Package kubernetes collects resource and performance metrics from a Kubernetes
// cluster via the API server and Kubelet stats endpoints, covering nodes, pods,
// deployments, services, namespaces, storage, network policies, HPAs, PDBs,
// workload controllers, events, and pod logs.
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
package kubernetes

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// collectWorkloads gathers StatefulSet, DaemonSet, ReplicaSet, Job, CronJob metrics.
func collectWorkloads(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	cluster string,
) ([]collector.Metric, []WorkloadState, []WorkloadState, []WorkloadState, []WorkloadState, []WorkloadState, error) {
	var (
		metrics    []collector.Metric
		stsStates  []WorkloadState
		dsStates   []WorkloadState
		rsStates   []WorkloadState
		jobStates  []WorkloadState
		cronStates []WorkloadState
	)

	opts := metav1.ListOptions{LabelSelector: cfg.LabelSelector}

	// --- StatefulSets ---
	stsList, err := cs.AppsV1().StatefulSets("").List(ctx, opts)
	if err == nil {
		for i := range stsList.Items {
			sts := &stsList.Items[i]
			if !cfg.shouldCollectNamespace(sts.Namespace) {
				continue
			}
			labels := map[string]string{
				"cluster":     cluster,
				"namespace":   sts.Namespace,
				"statefulset": sts.Name,
			}
			desired := int32(0)
			if sts.Spec.Replicas != nil {
				desired = *sts.Spec.Replicas
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.statefulset.replicas", float64(desired), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Desired replicas"),
				collector.NewMetric("k8s.statefulset.replicas.ready", float64(sts.Status.ReadyReplicas), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Ready replicas"),
			)
			stsStates = append(stsStates, WorkloadState{
				Kind: "StatefulSet", Name: sts.Name, Namespace: sts.Namespace,
				Desired: desired, Current: sts.Status.CurrentReplicas, Ready: sts.Status.ReadyReplicas,
			})
		}
	}

	// --- DaemonSets ---
	dsList, err := cs.AppsV1().DaemonSets("").List(ctx, opts)
	if err == nil {
		for i := range dsList.Items {
			ds := &dsList.Items[i]
			if !cfg.shouldCollectNamespace(ds.Namespace) {
				continue
			}
			labels := map[string]string{
				"cluster":   cluster,
				"namespace": ds.Namespace,
				"daemonset": ds.Name,
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.daemonset.desired", float64(ds.Status.DesiredNumberScheduled), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Desired number scheduled"),
				collector.NewMetric("k8s.daemonset.current", float64(ds.Status.CurrentNumberScheduled), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Current number scheduled"),
				collector.NewMetric("k8s.daemonset.ready", float64(ds.Status.NumberReady), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Number ready"),
			)
			dsStates = append(dsStates, WorkloadState{
				Kind: "DaemonSet", Name: ds.Name, Namespace: ds.Namespace,
				Desired: ds.Status.DesiredNumberScheduled, Current: ds.Status.CurrentNumberScheduled, Ready: ds.Status.NumberReady,
			})
		}
	}

	// --- ReplicaSets ---
	rsList, err := cs.AppsV1().ReplicaSets("").List(ctx, opts)
	if err == nil {
		for i := range rsList.Items {
			rs := &rsList.Items[i]
			if !cfg.shouldCollectNamespace(rs.Namespace) {
				continue
			}
			labels := map[string]string{
				"cluster":    cluster,
				"namespace":  rs.Namespace,
				"replicaset": rs.Name,
			}
			desired := int32(0)
			if rs.Spec.Replicas != nil {
				desired = *rs.Spec.Replicas
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.replicaset.replicas", float64(desired), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Desired replicas"),
				collector.NewMetric("k8s.replicaset.replicas.ready", float64(rs.Status.ReadyReplicas), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Ready replicas"),
			)
			rsStates = append(rsStates, WorkloadState{
				Kind: "ReplicaSet", Name: rs.Name, Namespace: rs.Namespace,
				Desired: desired, Current: rs.Status.Replicas, Ready: rs.Status.ReadyReplicas,
			})
		}
	}

	// --- Jobs ---
	jobList, err := cs.BatchV1().Jobs("").List(ctx, opts)
	if err == nil {
		for i := range jobList.Items {
			job := &jobList.Items[i]
			if !cfg.shouldCollectNamespace(job.Namespace) {
				continue
			}
			labels := map[string]string{
				"cluster":   cluster,
				"namespace": job.Namespace,
				"job":       job.Name,
			}
			metrics = append(metrics,
				collector.NewMetric("k8s.job.active", float64(job.Status.Active), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Active pod count"),
				collector.NewMetric("k8s.job.succeeded", float64(job.Status.Succeeded), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Succeeded pod count"),
				collector.NewMetric("k8s.job.failed", float64(job.Status.Failed), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Failed pod count"),
			)
			jobStates = append(jobStates, WorkloadState{
				Kind: "Job", Name: job.Name, Namespace: job.Namespace,
				Active: job.Status.Active, Succeeded: job.Status.Succeeded, Failed: job.Status.Failed,
			})
		}
	}

	// --- CronJobs ---
	cronList, err := cs.BatchV1().CronJobs("").List(ctx, opts)
	if err == nil {
		for i := range cronList.Items {
			cj := &cronList.Items[i]
			if !cfg.shouldCollectNamespace(cj.Namespace) {
				continue
			}
			labels := map[string]string{
				"cluster":   cluster,
				"namespace": cj.Namespace,
				"cronjob":   cj.Name,
			}
			activeCount := int32(len(cj.Status.Active))
			metrics = append(metrics,
				collector.NewMetric("k8s.cronjob.active", float64(activeCount), collector.MetricTypeGauge).
					WithLabels(labels).WithDescription("Active job count"),
			)
			cronStates = append(cronStates, WorkloadState{
				Kind: "CronJob", Name: cj.Name, Namespace: cj.Namespace,
				Active: activeCount,
			})
		}
	}

	return metrics, stsStates, dsStates, rsStates, jobStates, cronStates, nil
}
