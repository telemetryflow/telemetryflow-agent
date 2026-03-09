package kubernetes

import (
	"bufio"
	"context"
	"strings"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// collectPodLogs fetches a recent log tail for every running container across
// all pods (filtered by namespace rules). Only containers in Running status are
// targeted to avoid errors on terminated containers.
func collectPodLogs(
	ctx context.Context,
	cs kubernetes.Interface,
	cfg Config,
	logger *zap.Logger,
) ([]PodLogEntry, error) {
	tailLines := cfg.PodLogsTailLines
	if tailLines <= 0 {
		tailLines = 100
	}

	podList, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: cfg.LabelSelector,
	})
	if err != nil {
		return nil, err
	}

	var entries []PodLogEntry
	now := time.Now()

	for i := range podList.Items {
		pod := &podList.Items[i]

		// Namespace filter
		if !cfg.shouldCollectPodLogsNamespace(pod.Namespace) {
			continue
		}

		// Only collect logs from Running pods
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}

		for _, cst := range pod.Status.ContainerStatuses {
			if !cst.Ready {
				continue
			}

			req := cs.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{
				Container: cst.Name,
				TailLines: &tailLines,
			})

			rc, err := req.Stream(ctx)
			if err != nil {
				logger.Debug("Failed to stream pod logs",
					zap.String("namespace", pod.Namespace),
					zap.String("pod", pod.Name),
					zap.String("container", cst.Name),
					zap.Error(err),
				)
				continue
			}

			var lines []string
			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.TrimSpace(line) != "" {
					lines = append(lines, line)
				}
			}
			_ = rc.Close()

			if len(lines) == 0 {
				continue
			}

			entries = append(entries, PodLogEntry{
				Namespace:     pod.Namespace,
				PodName:       pod.Name,
				ContainerName: cst.Name,
				Lines:         lines,
				CollectedAt:   now,
			})
		}
	}

	return entries, nil
}

// shouldCollectPodLogsNamespace checks the PodLogsNamespaces allowlist first,
// then falls back to the regular namespace filter.
func (c *Config) shouldCollectPodLogsNamespace(ns string) bool {
	if len(c.PodLogsNamespaces) > 0 {
		for _, n := range c.PodLogsNamespaces {
			if n == ns {
				return true
			}
		}
		return false
	}
	return c.shouldCollectNamespace(ns)
}
