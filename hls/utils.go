package hls

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/CrazeeGhost/stalkerhek/stalker"
)

const userAgentFallback = "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 4 rev: 2116 Mobile Safari/533.3"

func download(link string, portal *stalker.Portal) (content []byte, contentType string, err error) {
	resp, err := response(link, portal)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	content, err = io.ReadAll(resp.Body)
	return content, resp.Header.Get("Content-Type"), err
}

// This Golang's HTTP client will not follow redirects.
//
// This is because by default it adds "Referrer" to the header, which causes
// 404 HTTP error in some backends. With below code such header is not added
// and redirects should be performed manually.
var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: 30 * time.Second,
}

func response(link string, portal *stalker.Portal) (*http.Response, error) {
	req, err := http.NewRequest("GET", link, nil)
	if err != nil {
		return nil, err
	}
	if portal != nil {
		stalker.ApplyPortalHeaders(req, portal, stalker.PortalReferer(portal))
	} else {
		req.Header.Set("User-Agent", userAgentFallback)
	}

	var resp *http.Response
	if portal != nil {
		resp, err = stalker.DoWithCFRetry(httpClient, req, stalker.CFRetryMaxAttempts)
	} else {
		resp, err = httpClient.Do(req)
	}
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}

	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		linkURL, err := url.Parse(link)
		if err != nil {
			return nil, errors.New("unknown error occurred")
		}
		redirectURL, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			return nil, errors.New("unknown error occurred")
		}
		newLink := linkURL.ResolveReference(redirectURL)
		return response(newLink.String(), portal)
	}

	return nil, errors.New(link + " returned HTTP code " + strconv.Itoa(resp.StatusCode))
}

func addHeaders(from, to http.Header, contentLength bool) {
	for k, v := range from {
		switch k {
		case "Connection":
			to.Set("Connection", strings.Join(v, "; "))
		case "Content-Type":
			to.Set("Content-Type", strings.Join(v, "; "))
		case "Transfer-Encoding":
			to.Set("Transfer-Encoding", strings.Join(v, "; "))
		case "Cache-Control":
			to.Set("Cache-Control", strings.Join(v, "; "))
		case "Date":
			to.Set("Date", strings.Join(v, "; "))
		case "Content-Length":
			// This is only useful for unaltered media files. It should not be copied for HLS requests because
			// players will not attempt to receive more bytes from HTTP server than are set here, therefore some HLS
			// contents would not load. E.g. CURL would display error "curl: (18) transfer closed with 83 bytes remaining to read"
			// if set for HLS metadata requests.
			if contentLength {
				to.Set("Content-Length", strings.Join(v, "; "))
			}
		}
	}
}

func getLinkType(contentType string) int {
	contentType = strings.ToLower(contentType)
	switch {
	case contentType == "application/vnd.apple.mpegurl" || contentType == "application/x-mpegurl":
		return linkTypeHLS
	case strings.HasPrefix(contentType, "video/") || strings.HasPrefix(contentType, "audio/") || contentType == "application/octet-stream":
		return linkTypeMedia
	default:
		return linkTypeMedia
	}
}
