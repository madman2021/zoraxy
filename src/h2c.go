package main

import (
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/tlscert"
)

// H2C shares only the public ingress and certificate store. Its manager owns
// domain routing, configuration, access checks and all upstream connections.
// The hook is registered once; edits only touch the manager's synchronized map.
func registerH2CProxyRouting(router *dynamicproxy.Router) error {
	if h2cProxyManager == nil {
		return nil
	}
	return router.AddRoutingRules(&dynamicproxy.RoutingRule{
		ID:                     "h2c-proxy",
		Enabled:                true,
		UseSystemAccessControl: false, // The manager enforces its selected access rule.
		MatchRule:              h2cProxyManager.Matches,
		RoutingHandler:         h2cProxyManager.ServeHTTP,
	})
}

func resolveProxyTLSBehavior(hostname string) (*tlscert.HostSpecificTlsBehavior, error) {
	if h2cProxyManager != nil && h2cProxyManager.OwnsDomain(hostname) {
		// Do not inherit TLS overrides from overlapping HTTP proxy rules.
		return tlscert.GetDefaultHostSpecificTlsBehavior(), nil
	}
	return dynamicProxyRouter.ResolveHostSpecificTlsBehaviorForHostname(hostname)
}
