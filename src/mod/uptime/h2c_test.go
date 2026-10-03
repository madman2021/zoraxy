package uptime

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestH2CUptimeCheck(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.URL.Path != "/health" {
			t.Errorf("unexpected health request: %s %s", r.Proto, r.URL.Path)
		}
		// A gRPC-only listener may reject GET while still being reachable.
		w.WriteHeader(http.StatusUnsupportedMediaType)
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	defer server.Close()

	var reachable bool
	monitor := &Monitor{Config: &Config{OnlineStateNotify: func(_ string, online bool) { reachable = online }}}
	_, _, statusCode := monitor.getWebsiteStatusWithLatency(&Target{
		URL:            server.URL,
		UseH2C:         true,
		HealthCheckURI: "/health",
	}, 5*time.Second)
	if statusCode != http.StatusUnsupportedMediaType || !reachable {
		t.Fatalf("status=%d reachable=%v", statusCode, reachable)
	}
}
