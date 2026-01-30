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

// Start connects to stalker portal, authenticates, starts watchdog etc.
func (p *Portal) Start() error {
	// Reserve token in Stalker portal
	if err := p.handshake(); err != nil {
		return err
	}

	// Authorize token if credentials or deviceids are given
	if p.Username != "" && p.Password != "" {
		if err := p.authenticate(); err != nil {
			return err
		}
	} else if p.DeviceIdAuth == true {
		if err := p.authenticateWithDeviceIDs(); err != nil {
			return err
		}
	}

	// Run watchdog function once to check for errors
	if err := p.watchdogUpdate(); err != nil {
		log.Println("Initial watchdog update failed:", err)
	}

	// Run watchdog function every x minutes (if configured)
	if p.WatchDogTime > 0 {
		log.Println("Enabling Watchdog Updates ... ")
		ticker := time.NewTicker(time.Duration(p.WatchDogTime) * time.Minute)
		go func() {
			for range ticker.C {
				if err := p.watchdogUpdate(); err != nil {
					log.Println("Watchdog update error:", err)
				}
			}
		}()
	} else {
		log.Println("Proceeding without Watchdog Updates")
	}
	return nil
}

func (p *Portal) httpRequest(link string) ([]byte, error) {
	req, err := http.NewRequest("GET", link, nil)
	if err != nil {
		return nil, err
	}

	// Use configured User‑Agent when provided; otherwise spoof a modern
	// desktop browser.  Some portals behind Cloudflare require that the
	// User‑Agent and cookies match those of a browser that solved the
	// challenge.
	ua := p.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("X-User-Agent", "Model: "+p.Model+"; Link: Ethernet")
	req.Header.Set("Authorization", "Bearer "+p.Token)
	// Add browser-like headers
	if u, err := url.Parse(p.Location); err == nil {
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
		req.Header.Set("Referer", p.Location)
	}
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-CH-UA", `"Chromium";v="114", "Not.A/Brand";v="24"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)

	// Build cookies (omit PHPSESSID=null)
	cookieText := "sn=" + url.QueryEscape(p.SerialNumber) + "; mac=" + url.QueryEscape(p.MAC) + "; stb_lang=en; timezone=" + url.QueryEscape(p.TimeZone) + ";"
	if p.Cookies != "" {
		if !strings.HasSuffix(cookieText, ";") {
			cookieText += ";"
		}
		cookieText += " " + p.Cookies
	}
	req.Header.Set("Cookie", cookieText)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("Site '" + link + "' returned " + resp.Status)
	}
	contents, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// If we received an HTML body that looks like Cloudflare, provide a clear hint
	if len(contents) > 0 && contents[0] == '<' {
		lower := strings.ToLower(string(contents))
		if strings.Contains(lower, "cloudflare") || strings.Contains(lower, "cf_clearance") {
			return nil, errors.New("cloudflare challenge detected: set portal.cookies with cf_clearance and portal.user_agent")
		}
	}
	return contents, nil
}

// WatchdogUpdate performs watchdog update request.
func (p *Portal) watchdogUpdate() error {
	type wdStruct struct {
		Js struct {
			Data struct {
				Msgs    int `json:"msgs"`
				Additional_services_on     string `json:"additional_services_on"`
			} `json:"data"`
		} `json:"js"`
		Text string `json:"text"`
	}
	var wd wdStruct
	content, err := p.httpRequest(p.Location + "?action=get_events&event_active_id=0&init=0&type=watchdog&cur_play_type=1&JsHttpRequest=1-xml")
	if err != nil {
		return err
	}
	
	if err := json.Unmarshal(content, &wd); err != nil {
		log.Fatalln("Watchdog update: "+string(content))
	}
	
	return nil
}
