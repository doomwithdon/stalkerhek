package stalker

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Cloudflare retry configuration.
const (
	CFRetryMaxAttempts = 3
	CFRetryInitialWait = 3 * time.Second
	CFRetryBackoff     = 2.0
)

// IsCloudflareResponse returns true when the response looks like a Cloudflare
// challenge or block (403/503 plus CF-RAY or Server: cloudflare).
func IsCloudflareResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusServiceUnavailable {
		return false
	}
	s := strings.ToLower(resp.Header.Get("Server"))
	ray := resp.Header.Get("CF-RAY")
	return strings.Contains(s, "cloudflare") || ray != ""
}

// ConsumeBody reads and discards the response body and closes it so the
// connection can be reused.
func ConsumeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// DoWithCFRetry performs the request with the given client. If the response
// is a Cloudflare challenge (403/503 + CF headers), it consumes the body,
// waits with exponential backoff, and retries up to maxAttempts times.
// The client must not follow redirects if the caller handles redirects itself.
// Each retry uses a cloned request; the original req is not reused after Do.
func DoWithCFRetry(client *http.Client, req *http.Request, maxAttempts int) (*http.Response, error) {
	if maxAttempts <= 0 {
		maxAttempts = CFRetryMaxAttempts
	}
	var resp *http.Response
	var err error
	wait := CFRetryInitialWait
	cur := req
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, err = client.Do(cur)
		if err != nil {
			return nil, err
		}
		if !IsCloudflareResponse(resp) {
			return resp, nil
		}
		ConsumeBody(resp)
		resp = nil
		if attempt == maxAttempts-1 {
			break
		}
		time.Sleep(wait)
		wait = time.Duration(float64(wait) * CFRetryBackoff)
		if wait > 15*time.Second {
			wait = 15 * time.Second
		}
		next := cur.Clone(cur.Context())
		if next != nil {
			cur = next
		}
	}
	return client.Do(cur)
}

// ApplyPortalHeaders sets User-Agent, Cookie, and optionally Referer on req
// using portal configuration. Used for stream/logo fetches (e.g. HLS) so
// Cloudflare and similar protection see browser-like headers and cf_clearance
// when configured.
func ApplyPortalHeaders(req *http.Request, p *Portal, referer string) {
	ua := p.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	}
	req.Header.Set("User-Agent", ua)
	cookie := "sn=" + url.QueryEscape(p.SerialNumber) + "; mac=" + url.QueryEscape(p.MAC) + "; stb_lang=en; timezone=" + url.QueryEscape(p.TimeZone)
	if p.Cookies != "" {
		if !strings.HasSuffix(cookie, ";") {
			cookie += ";"
		}
		cookie += " " + strings.TrimSpace(p.Cookies)
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
}

// PortalReferer returns the scheme+host of the portal URL to use as Referer
// for stream/logo requests (e.g. when same origin or CDN expects it).
func PortalReferer(p *Portal) string {
	if p == nil || p.Location == "" {
		return ""
	}
	u, err := url.Parse(p.Location)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/"
}
