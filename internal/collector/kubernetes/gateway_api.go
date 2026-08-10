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
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

// collectGatewayAPI gathers Gateway API (gateway.networking.k8s.io/v1) Gateway
// and HTTPRoute resources — used by NGINX Gateway Fabric (NGF) and any other
// Gateway API implementation.
//
// The Gateway API CRDs are OPTIONAL: they may be absent, or only installed at
// v1beta1/v1alpha2. When the group/version is missing (IsNotFound / NoMatch /
// discovery error) this returns empty slices and a nil error, logging at debug,
// so the overall cluster snapshot is never aborted.
func collectGatewayAPI(
	ctx context.Context,
	gc gatewayv.Interface,
	cfg Config,
	logger *zap.Logger,
) ([]GatewayState, []HTTPRouteState, error) {
	if gc == nil {
		return nil, nil, nil
	}

	gateways, err := collectGateways(ctx, gc, cfg)
	if err != nil {
		if isGatewayAPIAbsent(err) {
			logger.Debug("Gateway API CRDs not present, skipping Gateway/HTTPRoute collection", zap.Error(err))
			return []GatewayState{}, []HTTPRouteState{}, nil
		}
		return nil, nil, err
	}

	routes, err := collectHTTPRoutes(ctx, gc, cfg)
	if err != nil {
		if isGatewayAPIAbsent(err) {
			logger.Debug("HTTPRoute CRD not present, skipping HTTPRoute collection", zap.Error(err))
			return gateways, []HTTPRouteState{}, nil
		}
		return nil, nil, err
	}

	return gateways, routes, nil
}

// isGatewayAPIAbsent reports whether err indicates the Gateway API group/version
// is simply not installed on the cluster (as opposed to a real API failure).
func isGatewayAPIAbsent(err error) bool {
	if err == nil {
		return false
	}
	return apierrors.IsNotFound(err) || meta.IsNoMatchError(err)
}

// collectGateways lists Gateways in all namespaces and maps them to the contract.
func collectGateways(ctx context.Context, gc gatewayv.Interface, cfg Config) ([]GatewayState, error) {
	list, err := gc.GatewayV1().Gateways("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	states := make([]GatewayState, 0, len(list.Items))
	for i := range list.Items {
		gw := &list.Items[i]
		if !cfg.shouldCollectNamespace(gw.Namespace) {
			continue
		}

		// Listeners
		listeners := make([]GatewayListener, 0, len(gw.Spec.Listeners))
		for _, l := range gw.Spec.Listeners {
			tlsMode := ""
			if l.TLS != nil && l.TLS.Mode != nil {
				tlsMode = string(*l.TLS.Mode)
			}
			listeners = append(listeners, GatewayListener{
				Name:     string(l.Name),
				Protocol: string(l.Protocol),
				Port:     int32(l.Port),
				TLSMode:  tlsMode,
			})
		}

		// Addresses (from status)
		addresses := make([]GatewayAddress, 0, len(gw.Status.Addresses))
		for _, a := range gw.Status.Addresses {
			addrType := ""
			if a.Type != nil {
				addrType = string(*a.Type)
			}
			addresses = append(addresses, GatewayAddress{
				Type:  addrType,
				Value: a.Value,
			})
		}

		// Attached routes: sum across listener statuses
		var attached int32
		for _, ls := range gw.Status.Listeners {
			attached += ls.AttachedRoutes
		}

		states = append(states, GatewayState{
			Name:              gw.Name,
			Namespace:         gw.Namespace,
			GatewayClassName:  string(gw.Spec.GatewayClassName),
			Listeners:         listeners,
			Addresses:         addresses,
			AttachedRoutes:    attached,
			Status:            gatewayStatus(gw.Status.Conditions),
			CreationTimestamp: gw.CreationTimestamp.UTC().Format(time.RFC3339),
		})
	}
	return states, nil
}

// gatewayStatus derives a single status string from Gateway conditions.
func gatewayStatus(conditions []metav1.Condition) string {
	var programmed, accepted *metav1.ConditionStatus
	for i := range conditions {
		c := &conditions[i]
		switch c.Type {
		case string(gatewayv1.GatewayConditionProgrammed):
			s := c.Status
			programmed = &s
		case string(gatewayv1.GatewayConditionAccepted):
			s := c.Status
			accepted = &s
		}
	}
	switch {
	case programmed != nil && *programmed == metav1.ConditionTrue:
		return "Programmed"
	case programmed != nil && *programmed == metav1.ConditionFalse:
		return "NotProgrammed"
	case accepted != nil && *accepted == metav1.ConditionTrue:
		return "Accepted"
	default:
		return "Unknown"
	}
}

// collectHTTPRoutes lists HTTPRoutes in all namespaces and maps them.
func collectHTTPRoutes(ctx context.Context, gc gatewayv.Interface, cfg Config) ([]HTTPRouteState, error) {
	list, err := gc.GatewayV1().HTTPRoutes("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	states := make([]HTTPRouteState, 0, len(list.Items))
	for i := range list.Items {
		rt := &list.Items[i]
		if !cfg.shouldCollectNamespace(rt.Namespace) {
			continue
		}

		// Parent refs
		parents := make([]RouteParentRef, 0, len(rt.Spec.ParentRefs))
		for _, p := range rt.Spec.ParentRefs {
			ns := ""
			if p.Namespace != nil {
				ns = string(*p.Namespace)
			}
			section := ""
			if p.SectionName != nil {
				section = string(*p.SectionName)
			}
			parents = append(parents, RouteParentRef{
				Name:        string(p.Name),
				Namespace:   ns,
				SectionName: section,
			})
		}

		// Hostnames
		hostnames := make([]string, 0, len(rt.Spec.Hostnames))
		for _, h := range rt.Spec.Hostnames {
			hostnames = append(hostnames, string(h))
		}

		// Rules
		rules := make([]HTTPRouteRule, 0, len(rt.Spec.Rules))
		for ri := range rt.Spec.Rules {
			rule := &rt.Spec.Rules[ri]

			matches := make([]HTTPRouteMatch, 0, len(rule.Matches))
			for _, m := range rule.Matches {
				pathType, pathValue := "", ""
				if m.Path != nil {
					if m.Path.Type != nil {
						pathType = string(*m.Path.Type)
					}
					if m.Path.Value != nil {
						pathValue = *m.Path.Value
					}
				}
				method := ""
				if m.Method != nil {
					method = string(*m.Method)
				}
				matches = append(matches, HTTPRouteMatch{
					PathType:  pathType,
					PathValue: pathValue,
					Method:    method,
				})
			}

			backends := make([]RouteBackendRef, 0, len(rule.BackendRefs))
			for _, b := range rule.BackendRefs {
				ns := ""
				if b.Namespace != nil {
					ns = string(*b.Namespace)
				}
				var port int32
				if b.Port != nil {
					port = int32(*b.Port)
				}
				var weight int32
				if b.Weight != nil {
					weight = *b.Weight
				}
				backends = append(backends, RouteBackendRef{
					Name:      string(b.Name),
					Namespace: ns,
					Port:      port,
					Weight:    weight,
				})
			}

			rules = append(rules, HTTPRouteRule{
				Matches:     matches,
				BackendRefs: backends,
			})
		}

		states = append(states, HTTPRouteState{
			Name:              rt.Name,
			Namespace:         rt.Namespace,
			ParentRefs:        parents,
			Hostnames:         hostnames,
			Rules:             rules,
			CreationTimestamp: rt.CreationTimestamp.UTC().Format(time.RFC3339),
		})
	}
	return states, nil
}
