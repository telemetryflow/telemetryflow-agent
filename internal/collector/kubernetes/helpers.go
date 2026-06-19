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
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// parseCPU converts a resource.Quantity to millicores (int64).
func parseCPU(q resource.Quantity) int64 {
	return q.MilliValue()
}

// parseMemory converts a resource.Quantity to bytes (int64).
func parseMemory(q resource.Quantity) int64 {
	return q.Value()
}

// cpuToFloat converts millicores to cores as float64.
func cpuToFloat(millicores int64) float64 {
	return float64(millicores) / 1000.0
}

// nodeRoles extracts roles from a node's labels.
// Roles are defined by labels: node-role.kubernetes.io/<role>
func nodeRoles(node *corev1.Node) []string {
	var roles []string
	for key := range node.Labels {
		if strings.HasPrefix(key, "node-role.kubernetes.io/") {
			role := strings.TrimPrefix(key, "node-role.kubernetes.io/")
			if role != "" {
				roles = append(roles, role)
			}
		}
	}
	if len(roles) == 0 {
		roles = append(roles, "worker")
	}
	return roles
}

// nodeReady returns whether the node is in Ready condition.
func nodeReady(node *corev1.Node) bool {
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// nodeConditions returns a map of condition name → bool for all node conditions.
func nodeConditions(node *corev1.Node) map[string]bool {
	conds := make(map[string]bool, len(node.Status.Conditions))
	for _, c := range node.Status.Conditions {
		conds[string(c.Type)] = c.Status == corev1.ConditionTrue
	}
	return conds
}

// containerStatus returns a human-readable status string for a container.
func containerStatus(cs corev1.ContainerStatus) string {
	if cs.State.Running != nil {
		return "running"
	}
	if cs.State.Waiting != nil {
		return "waiting"
	}
	if cs.State.Terminated != nil {
		return "terminated"
	}
	return "unknown"
}

// ownerRef returns the first owner reference kind and name.
func ownerRef(pod *corev1.Pod) (kind, name string) {
	if len(pod.OwnerReferences) > 0 {
		return pod.OwnerReferences[0].Kind, pod.OwnerReferences[0].Name
	}
	return "", ""
}

// boolToFloat converts a bool to 0.0 or 1.0 for gauge metrics.
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// phaseToFloat maps a pod phase to a numeric gauge value:
// Running=1, Succeeded=2, Pending=3, Failed=4, Unknown=5
func phaseToFloat(phase corev1.PodPhase) float64 {
	switch phase {
	case corev1.PodRunning:
		return 1
	case corev1.PodSucceeded:
		return 2
	case corev1.PodPending:
		return 3
	case corev1.PodFailed:
		return 4
	default:
		return 5
	}
}

// parseResourceQuantity parses a Kubernetes quantity string (e.g. "500m", "2Gi").
func parseResourceQuantity(s string) (resource.Quantity, error) {
	return resource.ParseQuantity(s)
}

// ── Describe-level extraction helpers ─────────────────────────────────────

// extractTolerations converts K8s tolerations to TolerationState slice.
func extractTolerations(tolerations []corev1.Toleration) []TolerationState {
	if len(tolerations) == 0 {
		return nil
	}
	result := make([]TolerationState, 0, len(tolerations))
	for _, t := range tolerations {
		ts := TolerationState{
			Key:      t.Key,
			Operator: string(t.Operator),
			Value:    t.Value,
			Effect:   string(t.Effect),
		}
		if t.TolerationSeconds != nil {
			ts.TolerationSeconds = t.TolerationSeconds
		}
		result = append(result, ts)
	}
	return result
}

// extractVolumes converts K8s volumes to VolumeState slice.
func extractVolumes(volumes []corev1.Volume) []VolumeState {
	if len(volumes) == 0 {
		return nil
	}
	result := make([]VolumeState, 0, len(volumes))
	for _, v := range volumes {
		vs := VolumeState{
			Name:   v.Name,
			Source: make(map[string]string),
		}
		switch {
		case v.ConfigMap != nil:
			vs.Type = "configMap"
			vs.Source["name"] = v.ConfigMap.Name
		case v.Secret != nil:
			vs.Type = "secret"
			vs.Source["secretName"] = v.Secret.SecretName
		case v.EmptyDir != nil:
			vs.Type = "emptyDir"
			if v.EmptyDir.Medium != "" {
				vs.Source["medium"] = string(v.EmptyDir.Medium)
			}
		case v.PersistentVolumeClaim != nil:
			vs.Type = "persistentVolumeClaim"
			vs.Source["claimName"] = v.PersistentVolumeClaim.ClaimName
		case v.HostPath != nil:
			vs.Type = "hostPath"
			vs.Source["path"] = v.HostPath.Path
			if v.HostPath.Type != nil {
				vs.Source["type"] = string(*v.HostPath.Type)
			}
		case v.Projected != nil:
			vs.Type = "projected"
		case v.DownwardAPI != nil:
			vs.Type = "downwardAPI"
		case v.CSI != nil:
			vs.Type = "csi"
			vs.Source["driver"] = v.CSI.Driver
		default:
			vs.Type = "unknown"
		}
		result = append(result, vs)
	}
	return result
}

// extractVolumeMounts converts K8s volume mounts to VolumeMountState slice.
func extractVolumeMounts(mounts []corev1.VolumeMount) []VolumeMountState {
	if len(mounts) == 0 {
		return nil
	}
	result := make([]VolumeMountState, 0, len(mounts))
	for _, m := range mounts {
		result = append(result, VolumeMountState{
			Name:      m.Name,
			MountPath: m.MountPath,
			SubPath:   m.SubPath,
			ReadOnly:  m.ReadOnly,
		})
	}
	return result
}

// extractInitContainers builds ContainerState slice from pod init containers.
func extractInitContainers(pod *corev1.Pod) []ContainerState {
	if len(pod.Spec.InitContainers) == 0 {
		return nil
	}
	result := make([]ContainerState, 0, len(pod.Spec.InitContainers))
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		cs := ContainerState{
			Name:            c.Name,
			Image:           c.Image,
			CPURequest:      parseCPU(*c.Resources.Requests.Cpu()),
			CPULimit:        parseCPU(*c.Resources.Limits.Cpu()),
			MemoryRequest:   parseMemory(*c.Resources.Requests.Memory()),
			MemoryLimit:     parseMemory(*c.Resources.Limits.Memory()),
			VolumeMounts:    extractVolumeMounts(c.VolumeMounts),
			Command:         c.Command,
			Args:            c.Args,
			WorkingDir:      c.WorkingDir,
			ImagePullPolicy: string(c.ImagePullPolicy),
		}
		// Find init container status
		for _, ist := range pod.Status.InitContainerStatuses {
			if ist.Name == c.Name {
				cs.Ready = ist.Ready
				cs.RestartCount = ist.RestartCount
				cs.Status = containerStatus(ist)
				break
			}
		}
		result = append(result, cs)
	}
	return result
}

// extractProbe converts a K8s probe to a ProbeState summary.
func extractProbe(probe *corev1.Probe) *ProbeState {
	if probe == nil {
		return nil
	}
	ps := &ProbeState{
		InitialDelaySeconds: probe.InitialDelaySeconds,
		PeriodSeconds:       probe.PeriodSeconds,
		TimeoutSeconds:      probe.TimeoutSeconds,
		FailureThreshold:    probe.FailureThreshold,
		SuccessThreshold:    probe.SuccessThreshold,
	}
	switch {
	case probe.HTTPGet != nil:
		ps.Type = "httpGet"
		ps.Detail = fmt.Sprintf("%s %s:%s%s", probe.HTTPGet.Scheme, probe.HTTPGet.Host, probe.HTTPGet.Port.String(), probe.HTTPGet.Path)
	case probe.TCPSocket != nil:
		ps.Type = "tcpSocket"
		ps.Detail = probe.TCPSocket.Port.String()
	case probe.Exec != nil:
		ps.Type = "exec"
		ps.Detail = strings.Join(probe.Exec.Command, " ")
	case probe.GRPC != nil:
		ps.Type = "grpc"
		ps.Detail = fmt.Sprintf("port=%d", probe.GRPC.Port)
	}
	return ps
}

// extractNodeImages converts K8s node images to NodeImageState slice.
// Limits to top 50 images by size to avoid excessive payload.
func extractNodeImages(images []corev1.ContainerImage) []NodeImageState {
	if len(images) == 0 {
		return nil
	}
	limit := len(images)
	if limit > 50 {
		limit = 50
	}
	result := make([]NodeImageState, 0, limit)
	for i := 0; i < limit; i++ {
		result = append(result, NodeImageState{
			Names:     images[i].Names,
			SizeBytes: images[i].SizeBytes,
		})
	}
	return result
}

// extractNodeAddresses converts K8s node addresses to NodeAddressState slice.
func extractNodeAddresses(addresses []corev1.NodeAddress) []NodeAddressState {
	if len(addresses) == 0 {
		return nil
	}
	result := make([]NodeAddressState, 0, len(addresses))
	for _, a := range addresses {
		result = append(result, NodeAddressState{
			Type:    string(a.Type),
			Address: a.Address,
		})
	}
	return result
}

// extractNodeSystemInfo converts K8s NodeSystemInfo to NodeSystemInfoState.
func extractNodeSystemInfo(info corev1.NodeSystemInfo) *NodeSystemInfoState {
	return &NodeSystemInfoState{
		MachineID:               info.MachineID,
		SystemUUID:              info.SystemUUID,
		KernelVersion:           info.KernelVersion,
		OSImage:                 info.OSImage,
		ContainerRuntimeVersion: info.ContainerRuntimeVersion,
		KubeletVersion:          info.KubeletVersion,
		KubeProxyVersion:        info.KubeProxyVersion, //nolint:staticcheck // deprecated but still reported by nodes
		OperatingSystem:         info.OperatingSystem,
		Architecture:            info.Architecture,
	}
}
