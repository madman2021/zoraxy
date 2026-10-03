package h2cproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/access"
)

func h2cBackend(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.Config.Protocols = new(http.Protocols)
	s.Config.Protocols.SetUnencryptedHTTP2(true)
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func TestProxyMetadataPathsAndTrailers(t *testing.T) {
	backend := h2cBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Host != "backend.internal" {
			t.Errorf("upstream: %s %s", r.Proto, r.Host)
		}
		if r.URL.EscapedPath() != "/service/a%2Fb" || r.URL.RawQuery != "q=x%2Fy" {
			t.Errorf("URL = %s", r.URL)
		}
		if r.Header.Get("Te") != "trailers" || r.Header.Get("Authorization") != "Bearer test" {
			t.Error("metadata lost")
		}
		if r.Header.Get("X-Forwarded-For") != "192.0.2.1" || r.Header.Get("X-Real-IP") != "192.0.2.1" {
			t.Errorf("spoofable IP: %v", r.Header)
		}
		if r.Header.Get("X-Forwarded-Host") != "grpc.example.com" {
			t.Error("forwarded host lost")
		}
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "message")
		w.Header().Set("Grpc-Status", "7")
	}))
	m := testManager(t)
	_, err := m.Save(Config{Domain: "grpc.example.com", Target: backend.Listener.Addr().String(), Enabled: true, HostOverride: "backend.internal"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://grpc.example.com/service/a%2Fb?q=x%2Fy", strings.NewReader("payload"))
	r.Header.Set("Te", "trailers")
	r.Header.Set("Authorization", "Bearer test")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("X-Real-IP", "10.0.0.1")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	res := w.Result()
	defer res.Body.Close()
	if w.Code != 200 || w.Body.String() != "message" || res.Trailer.Get("Grpc-Status") != "7" {
		t.Fatalf("response: %d %q %v", w.Code, w.Body, res.Trailer)
	}
}

func TestProtocolAndAccessRejections(t *testing.T) {
	m := testManager(t)
	c := saveTestRule(t, m, "grpc.example.com", "127.0.0.1:1")
	for _, tc := range []struct {
		method, upgrade string
		status          int
	}{
		{http.MethodConnect, "", http.StatusMethodNotAllowed},
		{http.MethodGet, "websocket", http.StatusBadRequest},
		{http.MethodGet, "h2c", http.StatusBadRequest},
	} {
		r := httptest.NewRequest(tc.method, "http://grpc.example.com/", nil)
		r.Host = "grpc.example.com"
		r.Header.Set("Upgrade", tc.upgrade)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s %s = %d", tc.method, tc.upgrade, w.Code)
		}
	}
	m.options.AccessController.ProxyAccessRule.Store("selected", &access.AccessRule{})
	c.AccessRuleID = "selected"
	if _, err := m.Save(c); err != nil {
		t.Fatal(err)
	}
	m.options.AccessController.ProxyAccessRule.Delete("selected")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, httptest.NewRequest("POST", "http://grpc.example.com/service/method", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("deleted access rule: %d", w.Code)
	}
}

func TestNoHTTP1Fallback(t *testing.T) {
	var ordinaryRequests atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PRI" {
			ordinaryRequests.Add(1)
		} // The h2 preface can be parsed by an HTTP/1 server.
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	m := testManager(t)
	saveTestRule(t, m, "grpc.example.com", backend.Listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := httptest.NewRequest("POST", "http://grpc.example.com/service/method", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway || ordinaryRequests.Load() != 0 {
		t.Fatalf("fallback: status=%d requests=%d", w.Code, ordinaryRequests.Load())
	}
}

func TestConnectionReuseAndCleanup(t *testing.T) {
	var connections atomic.Int32
	closed := make(chan struct{}, 4)
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	backend.Config.Protocols = new(http.Protocols)
	backend.Config.Protocols.SetUnencryptedHTTP2(true)
	backend.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	backend.Start()
	defer backend.Close()
	m := testManager(t)
	c := saveTestRule(t, m, "grpc.example.com", backend.Listener.Addr().String())
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		m.ServeHTTP(w, httptest.NewRequest("GET", "https://grpc.example.com/", nil))
		if w.Code != 200 {
			t.Fatalf("request status = %d", w.Code)
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("connections = %d", connections.Load())
	}
	if err := m.SetEnabled(c.ID, false); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("idle connection not closed on stop")
	}
}

func TestRetiringServiceCancelsStreams(t *testing.T) {
	for _, action := range []string{"stop", "edit", "delete", "shutdown"} {
		t.Run(action, func(t *testing.T) {
			started := make(chan struct{})
			cancelled := make(chan struct{})
			backend := h2cBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				close(started)
				<-r.Context().Done()
				close(cancelled)
			}))
			m := testManager(t)
			c := saveTestRule(t, m, "grpc.example.com", backend.Listener.Addr().String())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				// ReverseProxy aborts a partially written response when a stream is cancelled.
				defer func() {
					if p := recover(); p != nil && p != http.ErrAbortHandler {
						panic(p)
					}
				}()
				m.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "http://grpc.example.com/stream", nil).WithContext(ctx))
			}()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("stream did not start")
			}
			var err error
			switch action {
			case "stop":
				err = m.SetEnabled(c.ID, false)
			case "edit":
				c.HostOverride = "changed.example.com"
				_, err = m.Save(c)
			case "delete":
				err = m.Delete(c.ID)
			case "shutdown":
				m.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-cancelled:
			case <-ctx.Done():
				t.Fatal("retirement did not cancel upstream")
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("proxy handler did not finish")
			}
		})
	}
}

func TestStoppingOneDomainLeavesOtherStreamsRunning(t *testing.T) {
	started := make(chan string, 2)
	finished := make(chan string, 2)
	backend := h2cBackend(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		started <- r.Host
		<-r.Context().Done()
		finished <- r.Host
	}))
	m := testManager(t)
	first := saveTestRule(t, m, "one.example.com", backend.Listener.Addr().String())
	saveTestRule(t, m, "two.example.com", backend.Listener.Addr().String())
	frontend := httptest.NewUnstartedServer(m)
	frontend.EnableHTTP2 = true
	frontend.StartTLS()
	defer frontend.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, domain := range []string{"one.example.com", "two.example.com"} {
		req, err := http.NewRequestWithContext(ctx, "POST", frontend.URL+"/stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = domain
		res, err := frontend.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("stream status = %d", res.StatusCode)
		}
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("stream did not start")
		}
	}
	if err := m.SetEnabled(first.ID, false); err != nil {
		t.Fatal(err)
	}
	select {
	case domain := <-finished:
		if domain != first.Domain {
			t.Fatalf("stopped wrong domain: %s", domain)
		}
	case <-ctx.Done():
		t.Fatal("stopped domain stream did not finish")
	}
	// The other domain still has a live service context and responds to new calls.
	m.mu.RLock()
	other := m.domains["two.example.com"]
	m.mu.RUnlock()
	if other.ctx.Err() != nil {
		t.Fatal("stopping one domain cancelled another")
	}
	select {
	case domain := <-finished:
		t.Fatalf("unexpected stream cancellation: %s", domain)
	default:
	}
}
