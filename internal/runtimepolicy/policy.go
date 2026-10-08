package runtimepolicy

import (
	"errors"
	xrpc "github.com/XGC-Team/xgc2-xrpc/go"
)

func Resolve(environment []string, role string) (*xrpc.Policy, error) {
	defaults := map[string]string{"HOST_MAX_CONNECTIONS": "16", "HOST_MAX_IN_FLIGHT": "8", "MAX_REQUEST_BYTES": "65536", "MAX_RESPONSE_BYTES": "65536", "CALL_TIMEOUT_MS": "30000"}
	capabilities := []string{"host", "http", "rpc", "transport"}
	ceilings := map[string]int64{"HOST_MAX_CONNECTIONS": 32, "HOST_MAX_IN_FLIGHT": 16, "MAX_REQUEST_BYTES": 65536, "MAX_RESPONSE_BYTES": 131072, "MAX_HEADER_BYTES": 16384, "CALL_TIMEOUT_MS": 30000}
	switch role {
	case "beacon":
	case "probe":
		defaults["HOST_MAX_CONNECTIONS"] = "32"
		defaults["HOST_MAX_IN_FLIGHT"] = "16"
		defaults["MAX_RESPONSE_BYTES"] = "131072"
		defaults["CLIENT_MAX_CONNECTIONS"] = "2"
		defaults["CLIENT_MAX_REFERENCES"] = "64"
		ceilings["CLIENT_MAX_CONNECTIONS"] = 2
		ceilings["CLIENT_MAX_REFERENCES"] = 64
		capabilities = append(capabilities, "client_pool", "client_registry")
	default:
		return nil, errors.New("unknown LAN process role")
	}
	return xrpc.ResolvePolicy(xrpc.PolicyOptions{Environment: environment, Defaults: defaults, DefaultSource: "lan-panel/" + role, Ceilings: ceilings, Capabilities: capabilities})
}
