package syncserver

// HTTP route constants for the sync server.
const (
	RouteHealthz      = "/healthz"
	RouteReadyz       = "/readyz"
	RouteRegister     = "/v1/auth/register"
	RouteRevoke       = "/v1/auth/revoke"
	RoutePush         = "/v1/vaults/{uuid}/push"
	RoutePull         = "/v1/vaults/{uuid}/pull"
	RouteStatus       = "/v1/vaults/{uuid}/status"
	RouteEvents       = "/v1/vaults/{uuid}/events"
	RouteDevices      = "/v1/vaults/{uuid}/devices"
	RouteHeartbeat    = "/v1/vaults/{uuid}/devices/heartbeat"
	RouteRevokeDevice = "/v1/vaults/{uuid}/devices/{device_id}/revoke"
	RouteAlerts       = "/v1/vaults/{uuid}/alerts"
)
