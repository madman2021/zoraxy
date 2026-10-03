package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/h2cproxy"
)

func TestH2CModuleDispatchAndACME(t *testing.T) {
	previous := h2cProxyManager
	t.Cleanup(func() { h2cProxyManager = previous })
	m, err := h2cproxy.NewManager(h2cproxy.Options{
		ConfigStore:      t.TempDir(),
		AccessController: &access.Controller{DefaultAccessRule: &access.AccessRule{ID: "default"}, ProxyAccessRule: &sync.Map{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	h2cProxyManager = m
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream protocol = %s", r.Proto)
		}
		io.WriteString(w, "h2c module")
	}))
	backend.Config.Protocols = new(http.Protocols)
	backend.Config.Protocols.SetUnencryptedHTTP2(true)
	backend.Start()
	defer backend.Close()
	c, err := m.Save(h2cproxy.Config{Domain: "grpc.example.com", Target: backend.Listener.Addr().String(), Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	// No HTTP endpoint, dpcore or load balancer is initialized in this router.
	router := &dynamicproxy.Router{}
	if err := registerH2CProxyRouting(router); err != nil {
		t.Fatal(err)
	}
	if err := router.AddRoutingRules(&dynamicproxy.RoutingRule{
		ID: "acme-test", Enabled: true,
		MatchRule:      func(r *http.Request) bool { return r.URL.Path == "/.well-known/acme-challenge/token" },
		RoutingHandler: func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "challenge") },
	}); err != nil {
		t.Fatal(err)
	}
	handler := &dynamicproxy.ProxyHandler{Parent: router}
	for _, tc := range []struct{ path, body string }{{"/service/method", "h2c module"}, {"/.well-known/acme-challenge/token", "challenge"}} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", "https://grpc.example.com"+tc.path, nil))
		if w.Code != 200 || w.Body.String() != tc.body {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
	if err := m.SetEnabled(c.ID, false); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "https://grpc.example.com/service/method", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("stopped service fell through: %d", w.Code)
	}
	behavior, err := resolveProxyTLSBehavior("grpc.example.com")
	if err != nil || behavior.DisableSNI || behavior.EnableAutoHTTPS {
		t.Fatalf("TLS behavior = %+v %v", behavior, err)
	}
}
