package stalker

import (
    "encoding/json"
    "errors"
    "io/ioutil"
    "log"
    "net/http"
    "strings"
    "time"
)

// Handshake reserves a offered token in Portal. If offered token is not available - new one will be issued by stalker portal, reservedMAG254 and Stalker's config will be updated.
func (p *Portal) handshake() error {
	// This HTTP request has different headers from the rest of HTTP requests, so perform it manually
	type tmpStruct struct {
		Js map[string]interface{} `json:"js"`
	}
	var tmp tmpStruct

    // Build handshake request and spoof a browser if a custom user agent is not provided.
    req, err := http.NewRequest("GET", p.Location+"?type=stb&action=handshake&token="+p.Token+"&JsHttpRequest=1-xml", nil)
    if err != nil {
        return err
    }
    ua := p.UserAgent
    if ua == "" {
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }
    req.Header.Set("User-Agent", ua)
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.5")
    req.Header.Set("Connection", "keep-alive")
    req.Header.Set("X-User-Agent", "Model: "+p.Model+"; Link: Ethernet")
    cookieText := "sn=" + p.SerialNumber + "; mac=" + p.MAC + "; stb_lang=en; timezone=" + p.TimeZone
    if p.Cookies != "" {
        if !strings.HasSuffix(cookieText, ";") {
            cookieText += ";"
        }
        cookieText += " " + p.Cookies
    }
    req.Header.Set("Cookie", cookieText)
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    // Detect Cloudflare challenge and retry once after a pause
    if (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusServiceUnavailable) &&
        (strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudflare") || resp.Header.Get("CF-RAY") != "") {
        ioutil.ReadAll(resp.Body)
        resp.Body.Close()
        time.Sleep(5 * time.Second)
        resp, err = client.Do(req)
        if err != nil {
            return err
        }
    }
    defer resp.Body.Close()
    contents, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return err
    }
    // Reject HTML responses which likely indicate that access has been blocked.
    if len(contents) > 0 && contents[0] == '<' {
        // Log the HTML content to aid debugging.
        log.Println(string(contents))
        return errors.New("stalker handshake returned HTML (possibly due to Cloudflare or invalid token)")
    }
    if err = json.Unmarshal(contents, &tmp); err != nil {
        log.Println(string(contents))
        return err
    }

	token, ok := tmp.Js["token"]
	if !ok || token == "" {
		// Token accepted. Using accepted token
		return nil
	}
	// Server provided new token. Using new provided token
	p.Token = token.(string)
	return nil
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
