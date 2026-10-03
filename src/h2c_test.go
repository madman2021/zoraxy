package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
)

func TestInvalidH2CUpdatePreservesExistingUpstream(t *testing.T) {
	previousRouter := dynamicProxyRouter
	t.Cleanup(func() { dynamicProxyRouter = previousRouter })

	upstream := &loadbalance.Upstream{OriginIpOrDomain: "collector:4317", UseH2C: true}
	endpoint := &dynamicproxy.ProxyEndpoint{
		RootOrMatchingDomain: "otel.example.com",
		ActiveOrigins:        []*loadbalance.Upstream{upstream},
	}
	dynamicProxyRouter = &dynamicproxy.Router{ProxyEndpoints: &sync.Map{}}
	dynamicProxyRouter.ProxyEndpoints.Store(endpoint.RootOrMatchingDomain, endpoint)

	form := url.Values{
		"ep":      {endpoint.RootOrMatchingDomain},
		"origin":  {upstream.OriginIpOrDomain},
		"payload": {`{"RequireTLS":true}`},
		"active":  {"true"},
	}
	request := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	ReverseProxyUpstreamUpdate(recorder, request)

	var result map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil || result["error"] == nil {
		t.Fatalf("expected configuration error, got %s", recorder.Body.String())
	}
	if len(endpoint.ActiveOrigins) != 1 || endpoint.ActiveOrigins[0] != upstream || upstream.RequireTLS {
		t.Fatal("rejected update changed the existing upstream")
	}
}

func TestH2CUptimeTargetUsesDedicatedProtocol(t *testing.T) {
	router := &dynamicproxy.Router{ProxyEndpoints: &sync.Map{}}
	router.ProxyEndpoints.Store("otel.example.com", &dynamicproxy.ProxyEndpoint{
		ActiveOrigins: []*loadbalance.Upstream{{OriginIpOrDomain: "collector:4317", UseH2C: true}},
	})
	targets := GetUptimeTargetsFromReverseProxyRules(router)
	if len(targets) != 1 || !targets[0].UseH2C || targets[0].Protocol != "h2c" || targets[0].URL != "http://collector:4317" {
		t.Fatalf("uptime targets = %+v", targets)
	}
}
