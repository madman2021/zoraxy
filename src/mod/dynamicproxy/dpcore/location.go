package dpcore

import (
	"net/http"
	"net/url"
	"strings"
)

// RewriteLocation applies Zoraxy's existing host/vdir redirect policy.
func RewriteLocation(header http.Header, rrr *ResponseRewriteRuleSet, downstreamTLS bool) {
	//Custom Location header rewriter functions
	if header.Get("Location") != "" {
		locationRewrite := header.Get("Location")
		originLocation := header.Get("Location")
		header.Set("zr-origin-location", originLocation)
		decodedOriginLocation, err := url.PathUnescape(originLocation)
		if err == nil {
			originLocation = decodedOriginLocation
		}
		if strings.HasPrefix(originLocation, "http://") || strings.HasPrefix(originLocation, "https://") {
			//Full path
			//Replace the forwarded target with expected Host
			lr, err := replaceLocationHost(locationRewrite, rrr, downstreamTLS)
			if err == nil {
				locationRewrite = lr
			}
		} else if strings.HasPrefix(originLocation, "/") && rrr.PathPrefix != "" {
			//Back to the root of this proxy host
			trimmedPrefix := strings.TrimSuffix(rrr.PathPrefix, "/")
			// Avoid double-prepending if the backend already returns a Location
			// See issue #1106
			if trimmedPrefix != "" && (strings.HasPrefix(originLocation, trimmedPrefix+"/") || originLocation == trimmedPrefix) {
				// Nginx location behavior: Upstream knows about the path prefix and has already included it in the Location header
				// e.g. PathPrefix=/proxy, backend returns Location: /proxy/foo, do not rewrite and keep it as /proxy/foo
				locationRewrite = originLocation
			} else {
				// Apache Virtual Directory behavior: Upstream is not aware of the path prefix and returns a Location header without the prefix.
				// We need to prepend the prefix to the Location header to make it work.
				// e.g. PathPrefix=/proxy, backend returns Location: /bar, rewrite to /proxy/bar
				locationRewrite = trimmedPrefix + originLocation
			}
		} else {
			//Relative path. Do not modifiy location header
		}

		//Custom redirection to this rproxy relative path
		header.Set("Location", locationRewrite)
	}
}
