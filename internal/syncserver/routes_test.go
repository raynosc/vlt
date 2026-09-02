package syncserver

import "testing"

func TestRoutes(t *testing.T) {
	want := map[string]string{
		"healthz":       "/healthz",
		"readyz":        "/readyz",
		"register":      "/v1/auth/register",
		"revoke":        "/v1/auth/revoke",
		"push":          "/v1/vaults/{uuid}/push",
		"pull":          "/v1/vaults/{uuid}/pull",
		"status":        "/v1/vaults/{uuid}/status",
		"devices":       "/v1/vaults/{uuid}/devices",
		"heartbeat":     "/v1/vaults/{uuid}/devices/heartbeat",
		"revoke_device": "/v1/vaults/{uuid}/devices/{device_id}/revoke",
		"alerts":        "/v1/vaults/{uuid}/alerts",
	}
	got := map[string]string{
		"healthz":       RouteHealthz,
		"readyz":        RouteReadyz,
		"register":      RouteRegister,
		"revoke":        RouteRevoke,
		"push":          RoutePush,
		"pull":          RoutePull,
		"status":        RouteStatus,
		"devices":       RouteDevices,
		"heartbeat":     RouteHeartbeat,
		"revoke_device": RouteRevokeDevice,
		"alerts":        RouteAlerts,
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Fatalf("missing route %s", name)
		}
		if g != w {
			t.Errorf("%s = %q, want %q", name, g, w)
		}
	}
}
