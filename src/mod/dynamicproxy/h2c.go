package dynamicproxy

import (
	"fmt"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy/dpcore"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/dynamicproxy/rewrite"
	"imuslab.com/zoraxy/mod/h2cproxy"
)

func validateUpstreamProtocol(protocol, address string, tls bool) error {
	switch protocol {
	case "", "http":
		return nil
	case "h2c":
		if tls {
			return fmt.Errorf("H2C requires a cleartext upstream; disable upstream TLS")
		}
		_, err := (h2cproxy.Upstream{Address: address}).URL()
		return err
	default:
		return fmt.Errorf("unknown upstream protocol %q", protocol)
	}
}

func (ep *ProxyEndpoint) ValidateUpstreamProtocol() error {
	validate := func(protocol, address string, tls bool) error {
		if protocol == "h2c" && (ep.ForceHTTP11 || ep.EnableConnectSupport || ep.EnableUpgradeForwarding || ep.DisableChunkedTransferEncoding) {
			return fmt.Errorf("H2C is incompatible with Force HTTP/1.1, CONNECT, generic upgrades or disabled streaming")
		}
		return validateUpstreamProtocol(protocol, address, tls)
	}
	// Validate the host protocol even when it has no origins.
	if err := validate(ep.UpstreamProtocol, "localhost", false); err != nil {
		return err
	}
	for _, origins := range [][]*loadbalance.Upstream{ep.ActiveOrigins, ep.InactiveOrigins} {
		for _, origin := range origins {
			if err := validate(ep.UpstreamProtocol, origin.OriginIpOrDomain, origin.RequireTLS); err != nil {
				return err
			}
		}
	}
	for _, vdir := range ep.VirtualDirectories {
		if err := validate(vdir.UpstreamProtocol, vdir.Domain, vdir.RequireTLS); err != nil {
			return err
		}
	}
	return nil
}

func (ep *ProxyEndpoint) h2cScope() string { return strings.ToLower(ep.RootOrMatchingDomain) }

// ConfigureH2C updates only dedicated H2C pools. Ordinary HTTP pools are untouched.
func (router *Router) ConfigureH2C(ep *ProxyEndpoint) error {
	if err := ep.ValidateUpstreamProtocol(); err != nil {
		return err
	}
	upstreams := make(map[string]h2cproxy.Upstream)
	if !ep.Disabled {
		if ep.UpstreamProtocol == "h2c" {
			for _, origin := range ep.ActiveOrigins {
				upstreams["origin:"+origin.OriginIpOrDomain] = h2cproxy.Upstream{
					Address: origin.OriginIpOrDomain, ResponseTimeoutMS: origin.RespTimeout, MaxConnections: origin.MaxConn,
				}
			}
		}
		for _, vdir := range ep.VirtualDirectories {
			if vdir.UpstreamProtocol == "h2c" && !vdir.Disabled {
				upstreams["vdir:"+vdir.MatchingPath] = h2cproxy.Upstream{Address: vdir.Domain}
			}
		}
	}
	return router.h2c.Configure(ep.h2cScope(), upstreams)
}

func (router *Router) startH2C() error {
	if err := router.ConfigureH2C(router.Root); err != nil {
		return err
	}
	var err error
	router.ProxyEndpoints.Range(func(_, value interface{}) bool {
		err = router.ConfigureH2C(value.(*ProxyEndpoint))
		return err == nil
	})
	return err
}

// h2cRequest runs after the existing host/vdir access and authentication gates.
// The module owns transport behavior; routing supplies request/response policy.
func (h *ProxyHandler) h2cRequest(w http.ResponseWriter, r *http.Request, ep *ProxyEndpoint, key, upstream, prefix string) {
	rules := ep.HeaderRewriteRules
	if rules == nil {
		rules = GetDefaultHeaderRewriteRules()
	}
	up, down := rewrite.SplitUpDownStreamHeaders(&rewrite.HeaderRewriteOptions{
		UserDefinedHeaders:           rewrite.PopulateRequestHeaderVariables(r, rules.UserDefinedHeaders),
		HSTSMaxAge:                   rules.HSTSMaxAge,
		HSTSIncludeSubdomains:        ep.ContainsWildcardName(true),
		EnablePermissionPolicyHeader: rules.EnablePermissionPolicyHeader,
		PermissionPolicy:             rules.PermissionPolicy,
	})
	host := r.Host
	status := h.Parent.h2c.ServeHTTP(ep.h2cScope(), key, w, r, &h2cproxy.Options{
		OriginalHost:        host,
		ClientIP:            h.Parent.GetClientIPForEndpoint(r, ep),
		HostHeaderOverwrite: rules.RequestHostOverwrite,
		UpstreamHeaders:     up, DownstreamHeaders: down,
		NoCache:                 h.Parent.Option.NoCache,
		NoRemoveUserAgentHeader: rules.DisableUserAgentHeaderRemoval,
		AltSvc:                  h.Parent.getAltSvcValue(),
		ModifyResponse: func(res *http.Response) error {
			dpcore.RewriteLocation(res.Header, &dpcore.ResponseRewriteRuleSet{
				ProxyDomain: upstream, OriginalHost: host, PathPrefix: prefix,
			}, r.TLS != nil)
			return nil
		},
	})
	h.Parent.logRequest(r, status < 400, status, "h2c", host, upstream, ep)
}
