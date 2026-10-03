package dynamicproxy

import (
	"encoding/json"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
)

func TestH2CConfigurationSurvivesSerialization(t *testing.T) {
	original := &ProxyEndpoint{
		RootOrMatchingDomain: "otel.example.com",
		ActiveOrigins: []*loadbalance.Upstream{{
			OriginIpOrDomain: "collector:4317",
			UseH2C:           true,
		}},
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var restored ProxyEndpoint
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if len(restored.ActiveOrigins) != 1 || !restored.ActiveOrigins[0].UseH2C {
		t.Fatalf("restored endpoint = %+v", restored.ActiveOrigins)
	}
}

func TestPrepareProxyRouteRejectsH2CWithForcedHTTP11(t *testing.T) {
	for _, inactive := range []bool{false, true} {
		endpoint := &ProxyEndpoint{ForceHTTP11: true}
		upstream := &loadbalance.Upstream{OriginIpOrDomain: "collector:4317", UseH2C: true}
		if inactive {
			endpoint.InactiveOrigins = []*loadbalance.Upstream{upstream}
		} else {
			endpoint.ActiveOrigins = []*loadbalance.Upstream{upstream}
		}
		if _, err := (&Router{}).PrepareProxyRoute(endpoint); err == nil {
			t.Fatalf("Force HTTP/1.1 accepted for h2c upstream (inactive=%v)", inactive)
		}
	}
}
