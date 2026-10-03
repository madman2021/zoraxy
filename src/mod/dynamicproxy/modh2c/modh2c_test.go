package modh2c

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newH2CServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func newProxy(t *testing.T, target string, options ProxyOptions) *Proxy {
	t.Helper()
	proxy, err := NewProxy(target, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.CloseIdleConnections)
	return proxy
}

func newFrontend(t *testing.T, proxy *Proxy, options RequestOptions) *httptest.Server {
	t.Helper()
	frontend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusCode, err := proxy.ServeHTTP(w, r, options)
		if err != nil {
			http.Error(w, err.Error(), statusCode)
		}
	}))
	frontend.EnableHTTP2 = true
	frontend.StartTLS()
	t.Cleanup(frontend.Close)
	return frontend
}

func TestProxyUsesH2CAndAppliesEndpointHeaders(t *testing.T) {
	backend := newH2CServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Errorf("upstream protocol = %q", r.Proto)
		}
		if r.Host != "collector.internal" {
			t.Errorf("upstream host = %q", r.Host)
		}
		if r.Header.Get("Te") != "trailers" {
			t.Errorf("TE header = %q", r.Header.Get("Te"))
		}
		if r.Header.Get("X-Project") != "telemetry" {
			t.Errorf("custom upstream header = %q", r.Header.Get("X-Project"))
		}
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("forwarded protocol = %q", r.Header.Get("X-Forwarded-Proto"))
		}
		if r.Header.Get("X-Forwarded-Host") != "public.example.com" {
			t.Errorf("forwarded host = %q", r.Header.Get("X-Forwarded-Host"))
		}
		if !strings.HasPrefix(r.Header.Get("X-Forwarded-For"), "203.0.113.10, ") {
			t.Errorf("forwarded chain = %q", r.Header.Get("X-Forwarded-For"))
		}
		if r.Header.Get("X-Real-Ip") != "203.0.113.10" {
			t.Errorf("real IP = %q", r.Header.Get("X-Real-Ip"))
		}
		w.Header().Set("User-Agent", "backend")
		w.Header().Set("Cache-Control", "public")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "accepted")
	}))

	proxy := newProxy(t, backend.URL, ProxyOptions{})
	frontend := newFrontend(t, proxy, RequestOptions{
		OriginalHost:        "public.example.com",
		HostHeaderOverwrite: "collector.internal",
		UpstreamHeaders:     [][]string{{"X-Project", "telemetry"}},
		DownstreamHeaders:   [][]string{{"X-Proxy-Test", "h2c"}},
		NoCache:             true,
		DevelopmentMode:     true,
		Version:             "test",
	})

	request, err := http.NewRequest(http.MethodPost, frontend.URL+"/v1/traces", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Te", "trailers")
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	response, err := frontend.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated || string(body) != "accepted" {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
	if response.Header.Get("X-Proxy-Test") != "h2c" || response.Header.Get("X-Proxy-By") != "zoraxy/test" {
		t.Fatalf("proxy headers = %v", response.Header)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("cache control = %q", response.Header.Get("Cache-Control"))
	}
	if response.Header.Get("User-Agent") != "" {
		t.Errorf("response User-Agent was not removed")
	}
}

func TestProxyForwardsResponseTrailers(t *testing.T) {
	backend := newH2CServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "message")
		w.Header().Set("Grpc-Status", "7")
		w.Header().Set("Grpc-Message", "permission denied")
	}))
	frontend := newFrontend(t, newProxy(t, backend.URL, ProxyOptions{}), RequestOptions{})

	response, err := frontend.Client().Get(frontend.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.Trailer.Get("Grpc-Status") != "7" || response.Trailer.Get("Grpc-Message") != "permission denied" {
		t.Fatalf("trailers = %v", response.Trailer)
	}
}

// An h2c backend may send response headers before the client supplies its
// first request message. The proxy must not read ahead and deadlock the pair.
func TestProxySupportsFullDuplexStreaming(t *testing.T) {
	backend := newH2CServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(w, r.Body)
	}))
	frontend := newFrontend(t, newProxy(t, backend.URL, ProxyOptions{}), RequestOptions{})

	reader, writer := io.Pipe()
	defer reader.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, frontend.URL+"/stream", reader)
	if err != nil {
		t.Fatal(err)
	}
	response, err := frontend.Client().Do(request)
	if err != nil {
		t.Fatalf("response headers waited for request body: %v", err)
	}
	defer response.Body.Close()

	go func() {
		_, _ = io.WriteString(writer, "stream-message")
		_ = writer.Close()
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "stream-message" {
		t.Fatalf("duplex response = %q, error = %v", body, err)
	}
}

func TestProxyPropagatesCancellation(t *testing.T) {
	requestCancelled := make(chan struct{})
	backend := newH2CServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(requestCancelled)
	}))
	frontend := newFrontend(t, newProxy(t, backend.URL, ProxyOptions{}), RequestOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, frontend.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := frontend.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	response.Body.Close()

	select {
	case <-requestCancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("client cancellation did not reach h2c upstream")
	}
}

func TestProxyNeverFallsBackToHTTP11(t *testing.T) {
	backendRequest := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendRequest <- r.Method + " " + r.Proto
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy := newProxy(t, backend.URL, ProxyOptions{ResponseHeaderTimeout: 2 * time.Second})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://public.example/", nil)
	statusCode, err := proxy.ServeHTTP(recorder, request, RequestOptions{})
	if err == nil || statusCode != http.StatusBadGateway {
		t.Fatalf("HTTP/1.1 backend: status=%d error=%v", statusCode, err)
	}
	select {
	case received := <-backendRequest:
		if received == http.MethodGet+" HTTP/1.1" {
			t.Fatal("h2c proxy fell back to an HTTP/1.1 request")
		}
	default:
	}
}

func TestProxyKeepsConcurrentRequestOptionsIsolated(t *testing.T) {
	backend := newH2CServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Host", r.Host)
		w.Header().Set("X-Seen-Request", r.Header.Get("X-Request"))
		w.WriteHeader(http.StatusOK)
	}))
	proxy := newProxy(t, backend.URL, ProxyOptions{})

	var wait sync.WaitGroup
	for _, value := range []string{"one", "two", "three", "four"} {
		value := value
		wait.Add(1)
		go func() {
			defer wait.Done()
			request := httptest.NewRequest(http.MethodGet, "http://public.example/", nil)
			recorder := httptest.NewRecorder()
			statusCode, err := proxy.ServeHTTP(recorder, request, RequestOptions{
				HostHeaderOverwrite: value + ".internal",
				UpstreamHeaders:     [][]string{{"X-Request", value}},
			})
			if err != nil || statusCode != http.StatusOK {
				t.Errorf("request %q: status=%d error=%v", value, statusCode, err)
				return
			}
			response := recorder.Result()
			if response.Header.Get("X-Seen-Host") != value+".internal" || response.Header.Get("X-Seen-Request") != value {
				t.Errorf("request %q received headers %v", value, response.Header)
			}
		}()
	}
	wait.Wait()
}

func TestProxyRejectsHTTP11OnlyOperations(t *testing.T) {
	proxy := newProxy(t, "localhost:4317", ProxyOptions{})

	connect := httptest.NewRequest(http.MethodConnect, "http://public.example", nil)
	connectRecorder := httptest.NewRecorder()
	statusCode, err := proxy.ServeHTTP(connectRecorder, connect, RequestOptions{})
	if err != nil || statusCode != http.StatusMethodNotAllowed {
		t.Fatalf("CONNECT: status=%d error=%v", statusCode, err)
	}

	upgrade := httptest.NewRequest(http.MethodGet, "http://public.example", nil)
	upgrade.Header.Set("Connection", "Upgrade")
	upgrade.Header.Set("Upgrade", "websocket")
	upgradeRecorder := httptest.NewRecorder()
	statusCode, err = proxy.ServeHTTP(upgradeRecorder, upgrade, RequestOptions{})
	if err != nil || statusCode != http.StatusBadRequest {
		t.Fatalf("upgrade: status=%d error=%v", statusCode, err)
	}
}

func TestValidateConfiguration(t *testing.T) {
	for _, testCase := range []struct {
		name, target             string
		useH2C, tls, http1, fail bool
	}{
		{name: "ordinary HTTPS", target: "example.com", tls: true},
		{name: "h2c", target: "localhost:4317", useH2C: true},
		{name: "explicit HTTP", target: "http://localhost:4317", useH2C: true},
		{name: "TLS flag", target: "localhost:4317", useH2C: true, tls: true, fail: true},
		{name: "HTTPS URL", target: "https://localhost:4317", useH2C: true, fail: true},
		{name: "forced HTTP1", target: "localhost:4317", useH2C: true, http1: true, fail: true},
		{name: "missing host", target: "http://", useH2C: true, fail: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := ValidateConfiguration(testCase.target, testCase.useH2C, testCase.tls, testCase.http1)
			if (err != nil) != testCase.fail {
				t.Fatalf("error = %v, want failure = %v", err, testCase.fail)
			}
		})
	}
}
