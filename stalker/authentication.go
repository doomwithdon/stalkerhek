package stalker

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Handshake reserves a offered token in Portal. If offered token is not available - new one will be issued by stalker portal, reservedMAG254 and Stalker's config will be updated.
func (p *Portal) handshake() error {
	// Warm up the portal to establish cookies (esp. behind Cloudflare)
	if err := p.portalWarmup(); err != nil {
		return err
	}

	type tmpStruct struct {
		Js map[string]interface{} `json:"js"`
	}
	var tmp tmpStruct

	buildReq := func(u string) (*http.Request, error) {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return nil, err
		}
		ua := p.UserAgent
		if ua == "" {
			ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("X-User-Agent", "Model: "+p.Model+"; Link: Ethernet")
		if base, err := url.Parse(p.Location); err == nil {
			req.Header.Set("Origin", base.Scheme+"://"+base.Host)
			req.Header.Set("Referer", p.Location)
			// Minimal sec-ch-* and sec-fetch headers to resemble Chrome
			req.Header.Set("Sec-Fetch-Dest", "empty")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Sec-CH-UA", `"Chromium";v="114", "Not.A/Brand";v="24"`)
			req.Header.Set("Sec-CH-UA-Mobile", "?0")
			req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
		}
		cookieText := "sn=" + url.QueryEscape(p.SerialNumber) + "; mac=" + url.QueryEscape(p.MAC) + "; stb_lang=en; timezone=" + url.QueryEscape(p.TimeZone)
		if p.Cookies != "" {
			if !strings.HasSuffix(cookieText, ";") {
				cookieText += ";"
			}
			cookieText += " " + p.Cookies
		}
		req.Header.Set("Cookie", cookieText)
		return req, nil
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// First attempt: with provided token
	withToken := p.Location + "?type=stb&action=handshake&token=" + p.Token + "&JsHttpRequest=1-xml"
	req, err := buildReq(withToken)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if isCloudflareAndRetry(resp) {
		resp.Body.Close()
		time.Sleep(5 * time.Second)
		resp, err = client.Do(req)
		if err != nil {
			return err
		}
	}
	contents, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if isHTML(contents) {
		// Retry without token (some portals issue a new token themselves)
		noToken := p.Location + "?type=stb&action=handshake&JsHttpRequest=1-xml"
		req2, err2 := buildReq(noToken)
		if err2 != nil {
			return err2
		}
		resp2, err2 := client.Do(req2)
		if err2 != nil {
			return err2
		}
		if isCloudflareAndRetry(resp2) {
			resp2.Body.Close()
			time.Sleep(5 * time.Second)
			resp2, err2 = client.Do(req2)
			if err2 != nil {
				return err2
			}
		}
		contents2, err2 := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		if err2 != nil {
			return err2
		}
		if isHTML(contents2) {
			log.Println(string(contents2))
			return errors.New("cloudflare or WAF blocked handshake: set portal.cookies (cf_clearance, etc.) and portal.user_agent to match your browser")
		}
		contents = contents2
	}

	if err = json.Unmarshal(contents, &tmp); err != nil {
		log.Println(string(contents))
		return err
	}

	token, ok := tmp.Js["token"]
	if !ok || token == "" {
		return nil
	}
	p.Token = token.(string)
	return nil
}

// portalWarmup performs a simple GET to the portal base URL to establish cookies
func (p *Portal) portalWarmup() error {
	req, err := http.NewRequest("GET", p.Location, nil)
	if err != nil {
		return err
	}
	ua := p.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	if base, err := url.Parse(p.Location); err == nil {
		req.Header.Set("Origin", base.Scheme+"://"+base.Host)
		req.Header.Set("Referer", p.Location)
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
	}
	cookieText := "sn=" + url.QueryEscape(p.SerialNumber) + "; mac=" + url.QueryEscape(p.MAC) + "; stb_lang=en; timezone=" + url.QueryEscape(p.TimeZone)
	if p.Cookies != "" {
		if !strings.HasSuffix(cookieText, ";") {
			cookieText += ";"
		}
		cookieText += " " + p.Cookies
	}
	req.Header.Set("Cookie", cookieText)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusForbidden && (strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudflare") || resp.Header.Get("CF-RAY") != "") {
		log.Println(string(body))
		return errors.New("cloudflare or WAF blocked warmup: ensure cf_clearance cookie and matching user_agent")
	}
	return nil
}

// isHTML returns true if the response body looks like HTML
func isHTML(b []byte) bool {
	return len(b) > 0 && b[0] == '<'
}

// isCloudflareAndRetry returns true if status is 403/503 and headers indicate Cloudflare
func isCloudflareAndRetry(resp *http.Response) bool {
	return (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusServiceUnavailable) &&
		(strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudflare") || resp.Header.Get("CF-RAY") != "")
}

// Authenticate associates credentials with token. In other words - logs you in
func (p *Portal) authenticate() (err error) {
	// This HTTP request has different headers from the rest of HTTP requests, so perform it manually
	type tmpStruct struct {
		Js   bool   `json:"js"`
		Text string `json:"text"`
	}
	var tmp tmpStruct

	content, err := p.httpRequest(p.Location + "?type=stb&action=do_auth&login=" + p.Username + "&password=" + p.Password + "&device_id=" + p.DeviceID + "&device_id2=" + p.DeviceID2 + "&JsHttpRequest=1-xml")
	if err != nil {
		log.Println("HTTP authentication request failed")
		return err
	}

    // Reject HTML responses which likely indicate that access has been blocked or returned an error page.
    if len(content) > 0 && content[0] == '<' {
        log.Println(string(content))
        return errors.New("authentication response was HTML (portal may be blocked by Cloudflare or credentials invalid)")
    }
    if err = json.Unmarshal(content, &tmp); err != nil {
        log.Println("parsing authentication response failed")
        return err
    }

	log.Println("Logging in to Stalker says:")
	log.Println(tmp.Text)

	if tmp.Js {
		// all good
		return nil
	}

	// questionable, but probably bad credentials
	return errors.New("invalid credentials")
}

// Authenticate with Device IDs
func (p *Portal) authenticateWithDeviceIDs() (err error) {
	// This HTTP request has different headers from the rest of HTTP requests, so perform it manually
	type tmpStruct struct {
		Js struct {
			Id string `json:"id"`
			Fname string `json:"fname"`
			} `json:"js"`
		Text string `json:"text"`
	}
	var tmp tmpStruct

	log.Println("Authenticating with DeviceId and DeviceId2")
	content, err := p.httpRequest(p.Location + "?type=stb&action=get_profile&JsHttpRequest=1-xml&hd=1&sn=" + p.SerialNumber + "&stb_type=" + p.Model + "&device_id=" + p.DeviceID + "&device_id2=" + p.DeviceID2 + "&auth_second_step=1")
	
	if err != nil {
		log.Println("HTTP authentication request failed")
		return err
	}

    // Reject HTML responses which likely indicate that access has been blocked or returned an error page.
    if len(content) > 0 && content[0] == '<' {
        log.Println(string(content))
        return errors.New("authentication response was HTML (portal may be blocked by Cloudflare or credentials invalid)")
    }
    if err = json.Unmarshal(content, &tmp); err != nil {
        log.Println("Unexpected authentication response")
        return err
    }

	log.Println("Logging in to Stalker says:")
	log.Println(tmp.Text)

	if tmp.Js.Id != "" {
		log.Println("Authenticated as " + tmp.Js.Fname)
		return nil
	}

	// questionable, but probably bad credentials
	return errors.New("invalid credentials")
}
