package loadbalance

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy/modh2c"
)

func TestUpstreamUsesDedicatedH2CProxy(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Protocol", r.Proto)
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "accepted")
	}))
	backend.Config.Protocols = new(http.Protocols)
	backend.Config.Protocols.SetUnencryptedHTTP2(true)
	backend.Start()
	defer backend.Close()

	upstream := &Upstream{
		OriginIpOrDomain: strings.TrimPrefix(backend.URL, "http://"),
		UseH2C:           true,
	}
	if err := upstream.StartProxy(""); err != nil {
		t.Fatal(err)
	}
	defer upstream.h2cProxy.CloseIdleConnections()
	if !upstream.IsReady() || upstream.proxy != nil || upstream.h2cProxy == nil {
		t.Fatal("h2c upstream did not initialize its dedicated proxy")
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://public.example/v1/traces", strings.NewReader("payload"))
	statusCode, err := upstream.ServeH2C(recorder, request, modh2c.RequestOptions{OriginalHost: request.Host})
	if err != nil {
		t.Fatal(err)
	}
	response := recorder.Result()
	defer response.Body.Close()
	if statusCode != http.StatusAccepted || response.Header.Get("X-Upstream-Protocol") != "HTTP/2.0" {
		t.Fatalf("status=%d headers=%v", statusCode, response.Header)
	}
}
