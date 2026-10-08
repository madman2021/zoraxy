package h2cproxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Upstream contains only settings that affect an H2C connection pool.
type Upstream struct {
	Address           string
	ResponseTimeoutMS int64
	MaxConnections    int
}

func (u Upstream) URL() (*url.URL, error) {
	address := u.Address
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	target, err := url.Parse(strings.TrimSuffix(address, "/"))
	if err != nil || target.Scheme != "http" || target.Host == "" || target.User != nil {
		return nil, fmt.Errorf("invalid cleartext H2C upstream %q", u.Address)
	}
	return target, nil
}

type pool struct {
	config Upstream
	proxy  *Proxy
}

// Manager owns H2C pools independently of the ordinary HTTP proxy. Its zero
// value is ready to use. Scopes are hosts; keys distinguish origins from vdirs.
type Manager struct {
	mu     sync.RWMutex
	scopes map[string]map[string]pool
}

// Configure reuses unchanged pools, including during metadata-only edits.
// Removed or changed upstreams are closed, canceling their active requests.
func (m *Manager) Configure(scope string, upstreams map[string]Upstream) error {
	urls := make(map[string]*url.URL, len(upstreams))
	for key, upstream := range upstreams {
		target, err := upstream.URL()
		if err != nil {
			return err
		}
		urls[key] = target
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.scopes[scope]
	next := make(map[string]pool, len(upstreams))
	for key, upstream := range upstreams {
		if old, ok := previous[key]; ok && old.config == upstream {
			next[key] = old
		} else {
			next[key] = pool{config: upstream, proxy: New(urls[key], upstream.ResponseTimeoutMS, upstream.MaxConnections)}
		}
	}
	for key, old := range previous {
		if next[key].proxy != old.proxy {
			old.proxy.Close()
		}
	}
	if m.scopes == nil {
		m.scopes = make(map[string]map[string]pool)
	}
	if len(next) == 0 {
		delete(m.scopes, scope)
	} else {
		m.scopes[scope] = next
	}
	return nil
}

func (m *Manager) ServeHTTP(scope, key string, w http.ResponseWriter, r *http.Request, opts *Options) int {
	m.mu.RLock()
	p := m.scopes[scope][key].proxy
	m.mu.RUnlock()
	if p == nil {
		http.Error(w, "H2C route unavailable", http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}
	status, _ := p.ServeHTTP(w, r, opts)
	return status
}

func (m *Manager) Remove(scope, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pool, ok := m.scopes[scope][key]; ok {
		pool.proxy.Close()
		delete(m.scopes[scope], key)
	}
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, pools := range m.scopes {
		for _, pool := range pools {
			pool.proxy.Close()
		}
	}
	m.scopes = nil
}
