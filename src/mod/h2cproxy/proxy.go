// Package h2cproxy forwards requests using HTTP/2 prior knowledge over cleartext.
// Routing, TLS termination, authentication and access policy belong to its caller.
package h2cproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Options carries request policy from the host/vdir router, not HTTP/1 options.
type Options struct {
	OriginalHost, ClientIP, HostHeaderOverwrite string
	UpstreamHeaders, DownstreamHeaders          [][]string
	NoCache, NoRemoveUserAgentHeader            bool
	AltSvc                                      string
	ModifyResponse                              func(*http.Response) error
}

type Proxy struct {
	target    *url.URL
	transport *http.Transport
	ctx       context.Context
	cancel    context.CancelFunc
}

// New owns a persistent HTTP/2-only pool. There is no HTTP/1 fallback.
func New(target *url.URL, responseTimeoutMS int64, maxConnections int) *Proxy {
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	ctx, cancel := context.WithCancel(context.Background())
	targetCopy := *target
	return &Proxy{target: &targetCopy, ctx: ctx, cancel: cancel, transport: &http.Transport{
		Protocols:             protocols,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: time.Duration(responseTimeoutMS) * time.Millisecond,
		MaxConnsPerHost:       maxConnections,
		DisableCompression:    true,
	}}
}

func (p *Proxy) Close() { p.cancel(); p.transport.CloseIdleConnections() }

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, opts *Options) (int, error) {
	if p.ctx.Err() != nil {
		http.Error(w, "Upstream route retired", http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable, nil
	}
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT is not supported by H2C", http.StatusMethodNotAllowed)
		return http.StatusMethodNotAllowed, nil
	}
	if r.Header.Get("Upgrade") != "" {
		http.Error(w, "Protocol upgrades are not supported by H2C", http.StatusBadRequest)
		return http.StatusBadRequest, nil
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(p.ctx, cancel)
	defer func() {
		stop()
		cancel()
		if p.ctx.Err() != nil {
			p.transport.CloseIdleConnections()
		}
	}()
	if r.ProtoMajor == 1 {
		_ = http.NewResponseController(w).EnableFullDuplex()
	}
	observer := &statusWriter{ResponseWriter: w}
	// Only the transport is shared: request-specific rules never mutate a
	// shared ReverseProxy while other requests are in flight.
	proxy := &httputil.ReverseProxy{
		Transport:     p.transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(p.target)
			pr.SetXForwarded()
			pr.Out.Host = opts.OriginalHost
			if opts.HostHeaderOverwrite != "" {
				pr.Out.Host = opts.HostHeaderOverwrite
			}
			pr.Out.Header.Set("X-Forwarded-Host", opts.OriginalHost)
			if opts.ClientIP != "" {
				pr.Out.Header.Set("X-Forwarded-For", opts.ClientIP)
				pr.Out.Header.Set("X-Real-IP", opts.ClientIP)
			}
			applyHeaders(pr.Out.Header, opts.UpstreamHeaders)
			stripHopHeaders(pr.Out.Header)
			if strings.EqualFold(pr.In.Header.Get("Te"), "trailers") {
				pr.Out.Header.Set("Te", "trailers")
			}
			if opts.NoCache {
				pr.Out.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
			}
		},
		ModifyResponse: func(res *http.Response) error {
			// A gRPC trailers-only response arrives as HTTP/2 response headers.
			// Immediate flushing can split those headers from END_STREAM on the
			// downstream connection. Emit the status as real trailers so clients
			// never mistake the following empty DATA frame for missing status.
			if strings.HasPrefix(strings.ToLower(res.Header.Get("Content-Type")), "application/grpc") && res.Header.Get("Grpc-Status") != "" {
				if res.Trailer == nil {
					res.Trailer = make(http.Header)
				}
				// All trailing application metadata shares this header block,
				// not just grpc-status. Keep HTTP framing fields as headers.
				for key, values := range res.Header {
					switch key {
					case "Content-Type", "Content-Length", "Date", "Server", "Trailer":
						continue
					}
					res.Trailer[key] = values
					res.Header.Del(key)
				}
			}
			if opts.ModifyResponse != nil {
				if err := opts.ModifyResponse(res); err != nil {
					return err
				}
			}
			applyHeaders(res.Header, opts.DownstreamHeaders)
			stripHopHeaders(res.Header)
			if !opts.NoRemoveUserAgentHeader {
				res.Header.Del("User-Agent")
			}
			if opts.NoCache {
				res.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
			}
			if opts.AltSvc != "" {
				res.Header.Set("Alt-Svc", opts.AltSvc)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "H2C upstream unavailable", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(observer, r.WithContext(ctx))
	return observer.status, nil
}

func applyHeaders(header http.Header, rules [][]string) {
	for _, rule := range rules {
		if len(rule) < 2 {
			continue
		}
		if rule[1] == "" {
			header.Del(rule[0])
		} else {
			header.Set(rule[0], rule[1])
		}
	}
}

func stripHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
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
