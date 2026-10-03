package h2cproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type service struct {
	config    Config
	ctx       context.Context
	cancel    context.CancelFunc
	transport *http.Transport
	proxy     *httputil.ReverseProxy
}

type clientIPKey struct{}

func newService(config Config) *service {
	ctx, cancel := context.WithCancel(context.Background())
	s := &service{config: config, ctx: ctx, cancel: cancel}
	if !config.Enabled {
		return s
	}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	s.transport = &http.Transport{
		Protocols:             protocols,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: time.Duration(config.ResponseHeaderTimeoutSeconds) * time.Second,
		DisableCompression:    true,
	}
	target := &url.URL{Scheme: "http", Host: config.Target}
	s.proxy = &httputil.ReverseProxy{
		Transport:     s.transport,
		FlushInterval: -1,
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(target)
			p.Out.Host = p.In.Host
			if config.HostOverride != "" {
				p.Out.Host = config.HostOverride
			}
			p.SetXForwarded()
			// Use the selected access rule's trusted-proxy resolution. Never
			// forward a client-supplied chain as an authoritative source IP.
			clientIP, _ := p.In.Context().Value(clientIPKey{}).(string)
			p.Out.Header.Set("X-Forwarded-For", clientIP)
			p.Out.Header.Set("X-Real-IP", clientIP)
			if strings.EqualFold(p.In.Header.Get("Te"), "trailers") {
				p.Out.Header.Set("Te", "trailers")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "H2C upstream unavailable", http.StatusBadGateway)
		},
	}
	return s
}

// Matches reserves configured domains even while stopped. ACME remains owned
// by Zoraxy's certificate service, including after its routing rule is renewed.
func (m *Manager) Matches(r *http.Request) bool {
	if r.URL != nil && strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		return false
	}
	return m.OwnsDomain(r.Host)
}

func (m *Manager) OwnsDomain(host string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.domains[requestDomain(host)]
	return ok
}

// ServeHTTP handles the entire domain with this module's access policy and
// protocol handler. HTTP proxy middleware, vdirs and rewrites do not apply.
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	s := m.domains[requestDomain(r.Host)]
	closed := m.closed
	m.mu.RUnlock()
	if s == nil {
		http.NotFound(w, r)
		return
	}
	if closed || !s.config.Enabled || s.ctx.Err() != nil {
		http.Error(w, "H2C service stopped", http.StatusServiceUnavailable)
		return
	}
	rule, err := m.options.AccessController.GetAccessRuleByID(s.config.AccessRuleID)
	if err != nil || rule == nil {
		// Fail closed if a selected access rule has been deleted.
		http.Error(w, "H2C access rule unavailable", http.StatusForbidden)
		return
	}
	clientIP := rule.GetClientIP(r)
	observer := &statusWriter{ResponseWriter: w}
	if s.config.EnableLogging && m.options.Logger != nil {
		defer func() {
			status := observer.status
			if status == 0 {
				status = http.StatusOK
			}
			m.options.Logger.LogHTTPRequest(r, "h2c", status, s.config.Domain, s.config.Target, clientIP)
		}()
	}
	if clientIP == "" || !rule.AllowIpAccess(clientIP) {
		http.Error(observer, "Forbidden", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		http.Error(observer, "CONNECT is not supported by H2C Proxy", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		http.Error(observer, "Protocol upgrades are not supported by H2C Proxy", http.StatusBadRequest)
		return
	}
	if r.ProtoMajor == 1 {
		// Permit simultaneous reading and writing for streaming HTTP/1 clients.
		_ = http.NewResponseController(w).EnableFullDuplex()
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(s.ctx, cancel)
	defer func() {
		stop()
		cancel()
		if s.ctx.Err() != nil {
			s.transport.CloseIdleConnections()
		}
	}()
	ctx = context.WithValue(ctx, clientIPKey{}, clientIP)
	s.proxy.ServeHTTP(observer, r.WithContext(ctx))
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if status >= 200 && w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
