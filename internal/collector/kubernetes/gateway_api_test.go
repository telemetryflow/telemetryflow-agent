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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telemetryflow/telemetryflow-agent/internal/config"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
)

func ptrTo[T any](v T) *T { return &v }

// newGWClient returns a fake Gateway API clientset seeded with the given
// Gateways/HTTPRoutes via Create (seeding through NewSimpleClientset's initial
// object list registers Gateway objects under the wrong GVR).
func newGWClient(t *testing.T, objs ...interface{}) *gatewayfake.Clientset {
	t.Helper()
	gc := gatewayfake.NewSimpleClientset()
	ctx := context.Background()
	for _, o := range objs {
		switch v := o.(type) {
		case *gatewayv1.Gateway:
			_, err := gc.GatewayV1().Gateways(v.Namespace).Create(ctx, v, metav1.CreateOptions{})
			require.NoError(t, err)
		case *gatewayv1.HTTPRoute:
			_, err := gc.GatewayV1().HTTPRoutes(v.Namespace).Create(ctx, v, metav1.CreateOptions{})
			require.NoError(t, err)
		default:
			t.Fatalf("newGWClient: unsupported object type %T", o)
		}
	}
	return gc
}

// testTime is a fixed creation timestamp used across fixtures.
var testTime = metav1.NewTime(time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC))

// programmedConditions returns a condition set whose derived status is "Programmed".
func programmedConditions() []metav1.Condition {
	return []metav1.Condition{
		{Type: string(gatewayv1.GatewayConditionAccepted), Status: metav1.ConditionTrue},
		{Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue},
	}
}

// buildGateway constructs a realistic Gateway fixture: one HTTP listener (no TLS)
// and one HTTPS listener (TLS Terminate), a status address, and per-listener
// attached-route counts.
func buildGateway(name, ns string) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         ns,
			CreationTimestamp: testTime,
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName("nginx"),
			Listeners: []gatewayv1.Listener{
				{
					Name:     gatewayv1.SectionName("http"),
					Protocol: gatewayv1.HTTPProtocolType,
					Port:     gatewayv1.PortNumber(80),
				},
				{
					Name:     gatewayv1.SectionName("https"),
					Protocol: gatewayv1.HTTPSProtocolType,
					Port:     gatewayv1.PortNumber(443),
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: ptrTo(gatewayv1.TLSModeTerminate),
					},
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{
				{Type: ptrTo(gatewayv1.IPAddressType), Value: "10.0.0.42"},
			},
			Listeners: []gatewayv1.ListenerStatus{
				{Name: gatewayv1.SectionName("http"), AttachedRoutes: 2},
				{Name: gatewayv1.SectionName("https"), AttachedRoutes: 3},
			},
			Conditions: programmedConditions(),
		},
	}
}

// buildHTTPRoute constructs an HTTPRoute with a cross-namespace parentRef using a
// sectionName, a hostname, a path/method match, and two weighted backendRefs
// (a stable + a canary).
func buildHTTPRoute(name, ns string) *gatewayv1.HTTPRoute {
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         ns,
			CreationTimestamp: testTime,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:        gatewayv1.ObjectName("public-gw"),
						Namespace:   ptrTo(gatewayv1.Namespace("infra")),
						SectionName: ptrTo(gatewayv1.SectionName("https")),
					},
				},
			},
			Hostnames: []gatewayv1.Hostname{"app.example.com"},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path: &gatewayv1.HTTPPathMatch{
								Type:  ptrTo(gatewayv1.PathMatchPathPrefix),
								Value: ptrTo("/api"),
							},
							Method: ptrTo(gatewayv1.HTTPMethodGet),
						},
					},
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("app-stable"),
									Port: ptrTo(gatewayv1.PortNumber(8080)),
								},
								Weight: ptrTo(int32(90)),
							},
						},
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name:      gatewayv1.ObjectName("app-canary"),
									Namespace: ptrTo(gatewayv1.Namespace("canary")),
									Port:      ptrTo(gatewayv1.PortNumber(8080)),
								},
								Weight: ptrTo(int32(10)),
							},
						},
					},
				},
			},
		},
	}
}

func TestCollectGateways(t *testing.T) {
	gc := newGWClient(t,
		buildGateway("gw-a", "team-a"),
		buildGateway("gw-b", "team-b"),
	)
	cfg := NewConfig(config.KubernetesCollectorConfig{})

	states, err := collectGateways(context.Background(), gc, cfg)
	require.NoError(t, err)
	require.Len(t, states, 2)

	// Fake clientset returns items sorted by namespace/name; locate gw-a.
	var gw *GatewayState
	for i := range states {
		if states[i].Name == "gw-a" {
			gw = &states[i]
		}
	}
	require.NotNil(t, gw, "gw-a should be present")

	assert.Equal(t, "gw-a", gw.Name)
	assert.Equal(t, "team-a", gw.Namespace)
	assert.Equal(t, "nginx", gw.GatewayClassName)
	assert.Equal(t, "Programmed", gw.Status)
	assert.Equal(t, int32(5), gw.AttachedRoutes) // 2 + 3 across listeners
	assert.Equal(t, "2026-08-11T10:30:00Z", gw.CreationTimestamp)

	// Listeners: one without TLS, one with TLS Terminate.
	require.Len(t, gw.Listeners, 2)
	assert.Equal(t, GatewayListener{Name: "http", Protocol: "HTTP", Port: 80, TLSMode: ""}, gw.Listeners[0])
	assert.Equal(t, GatewayListener{Name: "https", Protocol: "HTTPS", Port: 443, TLSMode: "Terminate"}, gw.Listeners[1])

	// Addresses from status.
	require.Len(t, gw.Addresses, 1)
	assert.Equal(t, GatewayAddress{Type: "IPAddress", Value: "10.0.0.42"}, gw.Addresses[0])
}

func TestCollectHTTPRoutes(t *testing.T) {
	gc := newGWClient(t, buildHTTPRoute("route-a", "team-a"))
	cfg := NewConfig(config.KubernetesCollectorConfig{})

	states, err := collectHTTPRoutes(context.Background(), gc, cfg)
	require.NoError(t, err)
	require.Len(t, states, 1)

	rt := states[0]
	assert.Equal(t, "route-a", rt.Name)
	assert.Equal(t, "team-a", rt.Namespace)
	assert.Equal(t, "2026-08-11T10:30:00Z", rt.CreationTimestamp)
	assert.Equal(t, []string{"app.example.com"}, rt.Hostnames)

	// Cross-namespace parentRef with a sectionName.
	require.Len(t, rt.ParentRefs, 1)
	assert.Equal(t, RouteParentRef{Name: "public-gw", Namespace: "infra", SectionName: "https"}, rt.ParentRefs[0])

	// Rule with a match + weighted backends.
	require.Len(t, rt.Rules, 1)
	rule := rt.Rules[0]
	require.Len(t, rule.Matches, 1)
	assert.Equal(t, HTTPRouteMatch{PathType: "PathPrefix", PathValue: "/api", Method: "GET"}, rule.Matches[0])

	require.Len(t, rule.BackendRefs, 2)
	assert.Equal(t, RouteBackendRef{Name: "app-stable", Namespace: "", Port: 8080, Weight: 90}, rule.BackendRefs[0])
	assert.Equal(t, RouteBackendRef{Name: "app-canary", Namespace: "canary", Port: 8080, Weight: 10}, rule.BackendRefs[1])
}

func TestCollectGatewaysNamespaceFiltering(t *testing.T) {
	gc := newGWClient(t,
		buildGateway("gw-a", "team-a"),
		buildGateway("gw-sys", "kube-system"),
	)
	// Exclude kube-system.
	cfg := NewConfig(config.KubernetesCollectorConfig{
		ExcludeNamespaces: []string{"kube-system"},
	})

	states, err := collectGateways(context.Background(), gc, cfg)
	require.NoError(t, err)
	require.Len(t, states, 1)
	assert.Equal(t, "team-a", states[0].Namespace)
}

func TestCollectHTTPRoutesNamespaceFiltering(t *testing.T) {
	gc := newGWClient(t,
		buildHTTPRoute("route-a", "team-a"),
		buildHTTPRoute("route-b", "team-b"),
	)
	// Explicit allow-list: only team-b.
	cfg := NewConfig(config.KubernetesCollectorConfig{
		Namespaces: []string{"team-b"},
	})

	states, err := collectHTTPRoutes(context.Background(), gc, cfg)
	require.NoError(t, err)
	require.Len(t, states, 1)
	assert.Equal(t, "team-b", states[0].Namespace)
}

func TestGatewayStatus(t *testing.T) {
	tests := []struct {
		name       string
		conditions []metav1.Condition
		expected   string
	}{
		{
			name: "programmed true",
			conditions: []metav1.Condition{
				{Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionTrue},
			},
			expected: "Programmed",
		},
		{
			name: "programmed false",
			conditions: []metav1.Condition{
				{Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionFalse},
			},
			expected: "NotProgrammed",
		},
		{
			name: "accepted true, no programmed",
			conditions: []metav1.Condition{
				{Type: string(gatewayv1.GatewayConditionAccepted), Status: metav1.ConditionTrue},
			},
			expected: "Accepted",
		},
		{
			name: "accepted false, no programmed",
			conditions: []metav1.Condition{
				{Type: string(gatewayv1.GatewayConditionAccepted), Status: metav1.ConditionFalse},
			},
			expected: "Unknown",
		},
		{
			name:       "no conditions",
			conditions: nil,
			expected:   "Unknown",
		},
		{
			name: "programmed false wins over accepted true",
			conditions: []metav1.Condition{
				{Type: string(gatewayv1.GatewayConditionAccepted), Status: metav1.ConditionTrue},
				{Type: string(gatewayv1.GatewayConditionProgrammed), Status: metav1.ConditionFalse},
			},
			expected: "NotProgrammed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, gatewayStatus(tc.conditions))
		})
	}
}

func TestIsGatewayAPIAbsent(t *testing.T) {
	gvr := schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gateways"}
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{name: "nil", err: nil, expected: false},
		{name: "not found", err: apierrors.NewNotFound(gvr, "x"), expected: true},
		{name: "no match", err: &meta.NoKindMatchError{}, expected: true},
		{name: "other error", err: apierrors.NewInternalError(assert.AnError), expected: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isGatewayAPIAbsent(tc.err))
		})
	}
}

func TestCollectGatewayAPINilClient(t *testing.T) {
	gws, routes, err := collectGatewayAPI(context.Background(), nil, NewConfig(config.KubernetesCollectorConfig{}), zap.NewNop())
	require.NoError(t, err)
	assert.Nil(t, gws)
	assert.Nil(t, routes)
}

func TestCollectGatewayAPIGracefulDegrade(t *testing.T) {
	gvr := schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gateways"}
	notFound := func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(gvr, "")
	}

	t.Run("gateways CRD absent", func(t *testing.T) {
		gc := gatewayfake.NewSimpleClientset()
		gc.PrependReactor("list", "gateways", notFound)

		gws, routes, err := collectGatewayAPI(context.Background(), gc, NewConfig(config.KubernetesCollectorConfig{}), zap.NewNop())
		require.NoError(t, err)
		assert.Equal(t, []GatewayState{}, gws)
		assert.Equal(t, []HTTPRouteState{}, routes)
	})

	t.Run("httproutes CRD absent, gateways present", func(t *testing.T) {
		fc := newGWClient(t, buildGateway("gw-a", "team-a"))
		fc.PrependReactor("list", "httproutes", notFound)
		var gc gatewayv.Interface = fc

		gws, routes, err := collectGatewayAPI(context.Background(), gc, NewConfig(config.KubernetesCollectorConfig{}), zap.NewNop())
		require.NoError(t, err)
		require.Len(t, gws, 1)
		assert.Equal(t, "gw-a", gws[0].Name)
		assert.Equal(t, []HTTPRouteState{}, routes)
	})
}
