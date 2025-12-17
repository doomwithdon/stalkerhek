package proxy

import (
    "io/ioutil"
    "net/http"
    "net/url"
    "strings"
    "time"
)

func getRequest(link string, originalRequest *http.Request) (*http.Response, error) {
	req, err := http.NewRequest("GET", link, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range originalRequest.Header {
		switch k {
		case "Authorization":
			req.Header.Set("Authorization", "Bearer "+config.Portal.Token)
		case "Cookie":
            cookieText := "PHPSESSID=null; sn=" + url.QueryEscape(config.Portal.SerialNumber) + "; mac=" + url.QueryEscape(config.Portal.MAC) + "; stb_lang=en; timezone=" + url.QueryEscape(config.Portal.TimeZone) + ";"
            // Append additional cookies such as cf_clearance if configured.
            if config.Portal.Cookies != "" {
                if !strings.HasSuffix(cookieText, ";") {
                    cookieText += ";"
                }
                cookieText += " " + config.Portal.Cookies
            }
            req.Header.Set("Cookie", cookieText)
		case "Referer":
		case "Referrer":
		default:
			req.Header.Set(k, v[0])
		}
	}

    // Override the User‑Agent header to the configured value if provided, or
    // set a sensible default.  Using a browser User‑Agent reduces the
    // likelihood of being blocked by middleware.
    if config.Portal.UserAgent != "" {
        req.Header.Set("User-Agent", config.Portal.UserAgent)
    } else if req.Header.Get("User-Agent") == "" {
        req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
    }

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    // Detect Cloudflare challenge pages and retry once after a pause.
    if (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusServiceUnavailable) &&
        (strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudflare") || resp.Header.Get("CF-RAY") != "") {
        // Consume and close body to free the underlying connection.
        ioutil.ReadAll(resp.Body)
        resp.Body.Close()
        time.Sleep(5 * time.Second)
        return client.Do(req)
    }
    return resp, nil
}

func addHeaders(from, to http.Header) {
	for k, v := range from {
		to.Set(k, strings.Join(v, "; "))
	}
}

func generateNewChannelLink(link, id, ch_id string) string {
	return `{"js":{"id":"` + id + `","cmd":"` + specialLinkEscape(link) + `","streamer_id":0,"link_id":` + ch_id + `,"load":0,"error":""},"text":"array(6) {\n  [\"id\"]=>\n  string(4) \"` + id + `\"\n  [\"cmd\"]=>\n  string(99) \"` + specialLinkEscape(link) + `\"\n  [\"streamer_id\"]=>\n  int(0)\n  [\"link_id\"]=>\n  int(` + ch_id + `)\n  [\"load\"]=>\n  int(0)\n  [\"error\"]=>\n  string(0) \"\"\n}\ngenerated in: 0.01s; query counter: 8; cache hits: 0; cache miss: 0; php errors: 0; sql errors: 0;"}`
}

func specialLinkEscape(i string) string {
	return strings.ReplaceAll(i, "/", "\\/")
}
