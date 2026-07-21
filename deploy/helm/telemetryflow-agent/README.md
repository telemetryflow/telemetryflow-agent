# TFO-Agent Helm Chart

Deploys the TFO-Agent to a Kubernetes cluster. The agent collects node-level OS metrics (via a DaemonSet) and Kubernetes cluster metrics (via a Deployment), and ships them to the TFO Platform via OTLP.

## Usage

```bash
helm install tfo-agent ./deploy/helm/telemetryflow-agent \
  --set telemetryflow.endpoint=https://platform.example.com \
  --set telemetryflow.apiKeyId=<key-id> \
  --set telemetryflow.apiKeySecret=<key-secret> \
  --set clusterName=my-cluster
```

### One-For-All Preset

Enables all four new capabilities (Prometheus scraper, remote write receiver, kubelet direct access, KSM gaps):

```bash
helm install tfo-agent ./deploy/helm/telemetryflow-agent \
  -f values-one-for-all.yaml \
  --set telemetryflow.endpoint=https://platform.example.com \
  --set telemetryflow.apiKeyId=<key-id> \
  --set telemetryflow.apiKeySecret=<key-secret>
```

## Values Reference

| Parameter                                                   | Description                                                                  | Default                                          |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------ |
| `telemetryflow.endpoint`                                    | TFO Platform API endpoint (REQUIRED)                                         | `""`                                             |
| `telemetryflow.apiKeyId`                                    | API key ID                                                                   | `""`                                             |
| `telemetryflow.apiKeySecret`                                | API key secret                                                               | `""`                                             |
| `telemetryflow.workspaceId`                                 | Workspace ID (multi-workspace)                                               | `""`                                             |
| `telemetryflow.tenantId`                                    | Tenant ID (multi-tenant)                                                     | `""`                                             |
| `clusterName`                                               | Cluster name injected as env var                                             | `""`                                             |
| `environment`                                               | Environment tag                                                              | `production`                                     |
| `oneForAll.enabled`                                         | Enable all four new capabilities                                             | `false`                                          |
| `image.repository`                                          | Container image repository                                                   | `ghcr.io/telemetryflow/tfo-agent`                |
| `image.pullPolicy`                                          | Image pull policy                                                            | `IfNotPresent`                                   |
| `image.tag`                                                 | Image tag (defaults to Chart.appVersion)                                     | `""`                                             |
| `imagePullSecrets`                                          | Image pull secrets                                                           | `[]`                                             |
| `hostNetwork`                                               | Use host network for node-level metrics                                      | `true`                                           |
| `dnsPolicy`                                                 | DNS policy                                                                   | `ClusterFirstWithHostNet`                        |
| `ports.otlpGrpc`                                            | OTLP gRPC port                                                               | `4317`                                           |
| `ports.otlpHttp`                                            | OTLP HTTP port                                                               | `4318`                                           |
| `ports.metrics`                                             | Prometheus metrics port                                                      | `8888`                                           |
| `ports.health`                                              | Health check port                                                            | `13133`                                          |
| `serviceAccount.create`                                     | Create service account                                                       | `true`                                           |
| `serviceAccount.name`                                       | Service account name (auto-generated if empty)                               | `""`                                             |
| `serviceAccount.annotations`                                | Service account annotations                                                  | `{}`                                             |
| `rbac.create`                                               | Create ClusterRole and ClusterRoleBinding                                    | `true`                                           |
| `nodeCollector.enabled`                                     | Enable node DaemonSet                                                        | `true`                                           |
| `kubernetesCollector.enabled`                               | Enable Kubernetes cluster Deployment                                         | `true`                                           |
| `kubernetesCollector.replicaCount`                          | Replica count for K8s collector                                              | `1`                                              |
| `kubernetesCollector.clusterName`                           | Cluster name for K8s collector                                               | `""`                                             |
| `kubernetesCollector.clusterProvider`                       | Kubernetes provider hint (eks, gke, aks, etc.)                               | `""`                                             |
| `kubernetesCollector.clusterId`                             | TFO cluster UUID (auto-registered if empty)                                  | `""`                                             |
| `kubernetesCollector.resources`                             | Resource limits for K8s collector                                            | see values.yaml                                  |
| `podSecurityContext`                                        | Pod-level security context                                                   | see values.yaml                                  |
| `nodeCollectorSecurityContext`                              | Container security context for node DaemonSet                                | see values.yaml                                  |
| `kubernetesCollectorSecurityContext`                        | Container security context for K8s Deployment                                | see values.yaml                                  |
| `nodeCollectorResources`                                    | Resource limits for node DaemonSet pods                                      | `cpu: 500m, memory: 512Mi`                       |
| `tolerations`                                               | Tolerations for DaemonSet                                                    | control-plane + master + not-ready + unreachable |
| `nodeSelector`                                              | Node selector for all pods                                                   | `{}`                                             |
| `affinity`                                                  | Affinity rules                                                               | `{}`                                             |
| `podAnnotations`                                            | Annotations added to all pods                                                | `{}`                                             |
| `commonLabels`                                              | Labels added to all resources                                                | `{}`                                             |
| `extraEnv`                                                  | Extra environment variables for all containers                               | `[]`                                             |
| `extraVolumes`                                              | Extra volumes for DaemonSet/Deployment pod spec                              | `[]`                                             |
| `extraVolumeMounts`                                         | Extra volume mounts for agent container                                      | `[]`                                             |
| `priorityClassName`                                         | Priority class for all pods (defaults to system-node-critical for DaemonSet) | `""`                                             |
| `podDisruptionBudget.enabled`                               | Enable PodDisruptionBudget                                                   | `false`                                          |
| `podDisruptionBudget.minAvailable`                          | Minimum available pods                                                       | `1`                                              |
| `config`                                                    | Base config for node DaemonSet                                               | see values.yaml                                  |
| `config.collectors.kubernetes.resource_quotas`              | Enable ResourceQuota metrics                                                 | `false`                                          |
| `config.collectors.kubernetes.limit_ranges`                 | Enable LimitRange metrics                                                    | `false`                                          |
| `config.collectors.kubernetes.pod_conditions`               | Enable per-pod condition metrics                                             | `false`                                          |
| `config.collectors.kubernetes.node_taints`                  | Enable per-node taint metrics                                                | `false`                                          |
| `config.collectors.kubernetes.workload_generations`         | Enable Deployment/StatefulSet generation metrics                             | `false`                                          |
| `config.collectors.kubernetes.kubelet_skip_verify` | Skip TLS verification for Kubelet connections                                | `false`                                          |
| `config.collectors.prometheus_scraper.enabled`              | Enable Prometheus pull-based scraper                                         | `false`                                          |
| `config.collectors.prometheus_scraper.scrape_jobs`          | List of scrape job configurations                                            | `[]`                                             |
| `config.collectors.remote_write_receiver.enabled`           | Enable Prometheus remote write receiver                                      | `false`                                          |
| `config.collectors.remote_write_receiver.port`              | Remote write receiver port                                                   | `9091`                                           |
| `kubernetes.config`                                         | Config override for K8s cluster collector Deployment                         | see values.yaml                                  |
