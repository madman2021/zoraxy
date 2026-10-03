// Package modh2c proxies HTTP requests to cleartext HTTP/2 upstreams.
//
// H2C is intentionally implemented outside dpcore. It has its own transport
// and reverse-proxy lifecycle because HTTP/1.1 connection upgrades, CONNECT
// tunnelling and several dpcore compatibility paths do not apply to HTTP/2.
package modh2c

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

var (
	ErrConnectNotSupported = errors.New("CONNECT tunnelling is not supported by an h2c upstream")
	ErrUpgradeNotSupported = errors.New("protocol upgrades are not supported by an h2c upstream")
)

// TransportOptions controls the connection pool owned by an h2c proxy.
type TransportOptions struct {
	MaxConcurrentConnections int
	ResponseHeaderTimeout    time.Duration
	DisableKeepAlives        bool
}

// NewTransport creates a transport that uses HTTP/2 prior knowledge over a
// cleartext TCP connection. It never falls back to HTTP/1.1.
func NewTransport(options TransportOptions) *http.Transport {
	maxConnections := options.MaxConcurrentConnections
	if maxConnections <= 0 {
		maxConnections = 256
	}

	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)

	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		Protocols:             protocols,
		MaxIdleConns:          maxConnections * 2,
		MaxIdleConnsPerHost:   maxConnections,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: options.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		DisableKeepAlives:     options.DisableKeepAlives,
	}
}

// ProxyOptions controls one reusable h2c proxy instance.
type ProxyOptions struct {
	FlushInterval            time.Duration
	MaxConcurrentConnections int
	ResponseHeaderTimeout    time.Duration
	ErrorLog                 *log.Logger
}

// RequestOptions contains the endpoint settings that remain meaningful for
// an h2c request. HTTP/1.1-only options are deliberately absent.
type RequestOptions struct {
	OriginalHost          string
	HostHeaderOverwrite   string
	UpstreamHeaders       [][]string
	DownstreamHeaders     [][]string
	NoCache               bool
	KeepResponseUserAgent bool
	DevelopmentMode       bool
	Version               string
	AltSvc                string
}

type requestState struct {
	options    RequestOptions
	statusCode int
	err        error
}

type requestStateKey struct{}

// Proxy owns a persistent connection pool and a reverse proxy for one h2c
// upstream. Proxy is safe for concurrent use.
type Proxy struct {
	target    *url.URL
	transport *http.Transport
	proxy     *httputil.ReverseProxy
}

// NewProxy creates a dedicated h2c proxy for target.
func NewProxy(target string, options ProxyOptions) (*Proxy, error) {
	parsedTarget, err := parseTarget(target)
	if err != nil {
		return nil, err
	}

	transport := NewTransport(TransportOptions{
		MaxConcurrentConnections: options.MaxConcurrentConnections,
		ResponseHeaderTimeout:    options.ResponseHeaderTimeout,
	})
	p := &Proxy{
		target:    parsedTarget,
		transport: transport,
	}

	flushInterval := options.FlushInterval
	if flushInterval == 0 {
		// H2C is primarily used for gRPC and other streaming protocols. Flush
		// each write unless the caller explicitly chooses another interval.
		flushInterval = -1
	}

	p.proxy = &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: flushInterval,
		ErrorLog:      options.ErrorLog,
		Rewrite:       p.rewriteRequest,
		ModifyResponse: func(response *http.Response) error {
			state, ok := stateFromContext(response.Request.Context())
			if !ok {
				return errors.New("h2c request state is missing")
			}
			state.statusCode = response.StatusCode
			modifyResponse(response, state.options)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, proxyErr error) {
			state, ok := stateFromContext(r.Context())
			if !ok {
				http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
				return
			}
			state.err = proxyErr
		},
	}

	return p, nil
}

func parseTarget(target string) (*url.URL, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("h2c target cannot be empty")
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}

	parsedTarget, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid h2c target: %w", err)
	}
	if !strings.EqualFold(parsedTarget.Scheme, "http") {
		return nil, errors.New("h2c requires a plaintext http target")
	}
	if parsedTarget.Host == "" {
		return nil, errors.New("h2c target must include a host")
	}
	return parsedTarget, nil
}

// ValidateConfiguration rejects settings that cannot be represented by an
// h2c connection. Non-h2c configurations are left untouched.
func ValidateConfiguration(target string, useH2C, requireTLS, forceHTTP11 bool) error {
	if !useH2C {
		return nil
	}
	if requireTLS {
		return errors.New("h2c cannot be combined with Require TLS")
	}
	if forceHTTP11 {
		return errors.New("h2c cannot be combined with Force HTTP/1.1")
	}
	_, err := parseTarget(target)
	return err
}

func (p *Proxy) rewriteRequest(proxyRequest *httputil.ProxyRequest) {
	state, ok := stateFromContext(proxyRequest.In.Context())
	if !ok {
		return
	}

	proxyRequest.SetURL(p.target)
	if prior := proxyRequest.In.Header.Values("X-Forwarded-For"); len(prior) > 0 {
		proxyRequest.Out.Header.Set("X-Forwarded-For", strings.Join(prior, ", "))
	}
	proxyRequest.SetXForwarded()
	setXRealIP(proxyRequest.Out.Header)
	if state.options.OriginalHost != "" {
		proxyRequest.Out.Header.Set("X-Forwarded-Host", state.options.OriginalHost)
	}

	host := state.options.OriginalHost
	if host == "" {
		host = proxyRequest.In.Host
	}
	if state.options.HostHeaderOverwrite != "" {
		host = state.options.HostHeaderOverwrite
	}
	proxyRequest.Out.Host = host

	// net/http removes hop-by-hop fields before Rewrite. TE: trailers is the
	// sole TE value allowed by HTTP/2 and is required by gRPC.
	if strings.EqualFold(proxyRequest.In.Header.Get("Te"), "trailers") {
		proxyRequest.Out.Header.Set("Te", "trailers")
	}

	if state.options.NoCache {
		setNoCache(proxyRequest.Out.Header)
	}
	injectHeaders(proxyRequest.Out.Header, state.options.UpstreamHeaders)
	if proxyRequest.Out.Header.Get("User-Agent") == "" {
		proxyRequest.Out.Header.Set("User-Agent", "Zoraxy/"+state.options.Version)
	}
}

func modifyResponse(response *http.Response, options RequestOptions) {
	if options.NoCache {
		setNoCache(response.Header)
	}
	if !options.KeepResponseUserAgent {
		response.Header.Del("User-Agent")
	}
	injectHeaders(response.Header, options.DownstreamHeaders)
	if options.DevelopmentMode {
		response.Header.Set("X-Proxy-By", "zoraxy/"+options.Version)
	}
	if options.AltSvc != "" {
		response.Header.Set("Alt-Svc", options.AltSvc)
	}
}

func injectHeaders(header http.Header, rules [][]string) {
	for _, rule := range rules {
		if len(rule) < 2 || rule[0] == "" {
			continue
		}
		header.Del(rule[0])
		if rule[1] != "" {
			header.Set(rule[0], rule[1])
		}
	}
}

func setNoCache(header http.Header) {
	header.Del("Cache-Control")
	header.Set("Cache-Control", "no-store")
}

func setXRealIP(header http.Header) {
	if header.Get("X-Real-Ip") != "" {
		return
	}
	if clientIP := header.Get("CF-Connecting-IP"); clientIP != "" {
		header.Set("X-Real-Ip", clientIP)
		return
	}
	if clientIP := header.Get("Fastly-Client-IP"); clientIP != "" {
		header.Set("X-Real-Ip", clientIP)
		return
	}
	if forwardedFor := header.Get("X-Forwarded-For"); forwardedFor != "" {
		header.Set("X-Real-Ip", strings.TrimSpace(strings.Split(forwardedFor, ",")[0]))
	}
}

func stateFromContext(ctx context.Context) (*requestState, bool) {
	state, ok := ctx.Value(requestStateKey{}).(*requestState)
	return state, ok
}

func upgradeType(header http.Header) string {
	for _, token := range strings.Split(header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return header.Get("Upgrade")
		}
	}
	return ""
}

// statusResponseWriter observes the final response status while preserving
// optional ResponseWriter capabilities through Unwrap.
type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusResponseWriter) WriteHeader(statusCode int) {
	// Informational responses are not the final request status.
	if statusCode >= 200 && w.statusCode == 0 {
		w.statusCode = statusCode
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusResponseWriter) Write(body []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

func (w *statusResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// ServeHTTP proxies one request and reports its final status. Request-scoped
// endpoint options are kept outside the shared Proxy so concurrent requests
// cannot overwrite one another.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, options RequestOptions) (int, error) {
	if r.Method == http.MethodConnect {
		http.Error(w, ErrConnectNotSupported.Error(), http.StatusMethodNotAllowed)
		return http.StatusMethodNotAllowed, nil
	}
	if upgradeType(r.Header) != "" {
		http.Error(w, ErrUpgradeNotSupported.Error(), http.StatusBadRequest)
		return http.StatusBadRequest, nil
	}

	state := &requestState{options: options}
	ctx := context.WithValue(r.Context(), requestStateKey{}, state)
	outRequest := r.Clone(ctx)
	observer := &statusResponseWriter{ResponseWriter: w}
	p.proxy.ServeHTTP(observer, outRequest)

	if state.err != nil {
		return http.StatusBadGateway, state.err
	}
	if observer.statusCode != 0 {
		return observer.statusCode, nil
	}
	if state.statusCode != 0 {
		return state.statusCode, nil
	}
	return http.StatusOK, nil
}

// CloseIdleConnections releases idle upstream connections owned by this proxy.
func (p *Proxy) CloseIdleConnections() {
	p.transport.CloseIdleConnections()
}
