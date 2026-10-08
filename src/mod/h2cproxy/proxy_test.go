package h2cproxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestH2CForwarding(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream protocol = %s, want HTTP/2", r.Proto)
		}
		w.Header().Set("Trailer", "Grpc-Status")
		fmt.Fprint(w, r.URL.RequestURI())
		w.Header().Set("Grpc-Status", "0")
	}))
	backend.Config.Protocols = new(http.Protocols)
	backend.Config.Protocols.SetUnencryptedHTTP2(true)
	backend.Start()
	defer backend.Close()

	var manager Manager
	defer manager.Close()
	upstreams := map[string]Upstream{"origin": {Address: backend.URL}}
	if err := manager.Configure("example.com", upstreams); err != nil {
		t.Fatal(err)
	}
	pool := manager.scopes["example.com"]["origin"].proxy
	if err := manager.Configure("example.com", upstreams); err != nil {
		t.Fatal(err)
	}
	if manager.scopes["example.com"]["origin"].proxy != pool {
		t.Fatal("unchanged configuration replaced the H2C pool")
	}

	request := httptest.NewRequest("POST", "http://example.com/service/method?x=1", nil)
	response := httptest.NewRecorder()
	opts := &Options{OriginalHost: "example.com"}
	status := manager.ServeHTTP("example.com", "origin", response, request, opts)
	if status != 200 || response.Body.String() != "/service/method?x=1" {
		t.Fatalf("response: %d %q", status, response.Body.String())
	}
	if got := response.Result().Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("gRPC trailer = %q, want 0", got)
	}
	manager.Remove("example.com", "origin")
	if status := manager.ServeHTTP("example.com", "origin", httptest.NewRecorder(), request, opts); status != 503 {
		t.Fatalf("removed route returned %d, want 503", status)
	}
}
