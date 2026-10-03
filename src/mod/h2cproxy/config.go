// Package h2cproxy manages domain-level cleartext HTTP/2 proxy services.
// It owns its configuration and transports independently of dynamicproxy.
package h2cproxy

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Config assigns an entire hostname to one h2c backend. Enabled is persisted,
// so stopped services stay stopped across restarts.
type Config struct {
	ID                           string
	Domain                       string
	Target                       string
	Enabled                      bool
	AccessRuleID                 string
	HostOverride                 string
	ResponseHeaderTimeoutSeconds int
	EnableLogging                bool
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if len(domain) == 0 || len(domain) > 253 || net.ParseIP(domain) != nil {
		return "", errors.New("domain must be an exact DNS hostname, without a scheme, port or wildcard")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid domain label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("domain must be an exact DNS hostname; use punycode for international names")
			}
		}
	}
	return domain, nil
}

func requestDomain(host string) string {
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		host = hostname
	}
	domain, _ := normalizeDomain(host)
	return domain
}

func normalizeConfig(config Config) (Config, error) {
	domain, err := normalizeDomain(config.Domain)
	if err != nil {
		return config, err
	}
	config.Domain = domain
	target := strings.TrimSpace(config.Target)
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return config, errors.New("target must be a plaintext host:port, without credentials, a path, query or fragment")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" {
		return config, errors.New("target must include a host and port, e.g. collector:4317")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return config, errors.New("target port must be between 1 and 65535")
	}
	if net.ParseIP(host) == nil {
		if _, err := normalizeDomain(host); err != nil {
			return config, errors.New("invalid target hostname")
		}
	}
	config.Target = net.JoinHostPort(strings.ToLower(host), strconv.Itoa(p))
	config.HostOverride = strings.TrimSpace(config.HostOverride)
	if config.HostOverride != "" {
		host := config.HostOverride
		if h, port, err := net.SplitHostPort(host); err == nil {
			host = h
			p, err := strconv.Atoi(port)
			if err != nil || p < 1 || p > 65535 {
				return config, errors.New("invalid host override port")
			}
		}
		if net.ParseIP(host) == nil {
			if _, err := normalizeDomain(host); err != nil {
				return config, errors.New("invalid host override")
			}
		}
	}
	if config.ResponseHeaderTimeoutSeconds < 0 || config.ResponseHeaderTimeoutSeconds > 86400 {
		return config, errors.New("response header timeout must be 0 to 86400 seconds (0 disables it)")
	}
	if config.AccessRuleID == "" {
		config.AccessRuleID = "default"
	}
	return config, nil
}
