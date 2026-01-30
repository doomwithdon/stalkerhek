package stalker

import (
	"errors"
	"io/ioutil"
	"log"
	"math/rand"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
)

// Config contains configuration taken from the YAML file.
type Config struct {
	Portal *Portal `yaml:"portal"`
	HLS    struct {
		Enabled bool   `yaml:"enabled"`
		Bind    string `yaml:"bind"`
	} `yaml:"hls"`
	Proxy struct {
		Enabled bool   `yaml:"enabled"`
		Bind    string `yaml:"bind"`
		Rewrite bool   `yaml:"rewrite"`
	} `yaml:"proxy"`
    // Admin section describes settings for the built‑in web administration UI.
    // When enabled the application will start a simple HTTP server that exposes
    // a form for editing the portal configuration and a button to restart the
    // application.  The Admin service listens on the address specified by
    // Bind.  If enabled, it can be used to update the YAML configuration
    // dynamically at runtime.  See admin/admin.go for implementation.
    Admin struct {
        Enabled bool   `yaml:"enabled"`
        Bind    string `yaml:"bind"`
    } `yaml:"admin"`
}

// Portal represents Stalker portal
type Portal struct {
	Model        string `yaml:"model"`
	SerialNumber string `yaml:"serial_number"`
	DeviceID     string `yaml:"device_id"`
	DeviceID2    string `yaml:"device_id2"`
	Signature    string `yaml:"signature"`
	MAC          string `yaml:"mac"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	Location     string `yaml:"url"`
	TimeZone     string `yaml:"time_zone"`
	Token        string `yaml:"token"`
	WatchDogTime int `yaml:"watchdog"`
	DeviceIdAuth bool `yaml:"device_id_auth"`

    // UserAgent allows overriding the default User‑Agent header used when
    // connecting to the Stalker portal.  Some middleware (such as
    // Cloudflare) may challenge unknown clients.  Providing a User‑Agent
    // string copied from a real browser can help bypass such checks.
    UserAgent string `yaml:"user_agent"`

    // Cookies allows specifying additional cookies that will be sent with
    // each request to the Stalker portal.  When the portal is protected
    // behind Cloudflare, a valid `cf_clearance` cookie obtained by
    // completing the challenge in a browser can be placed here (e.g.
    // "cf_clearance=longvalue").  The cookie is appended to the
    // internally generated cookies.
    Cookies string `yaml:"cookies"`
}

// ReadConfig returns configuration from the file in Portal object
func ReadConfig(path *string) (*Config, error) {
	content, err := ioutil.ReadFile(*path)
	if err != nil {
		return nil, err
	}

	var c *Config
	err = yaml.Unmarshal(content, &c)
	if err != nil {
		return nil, err
	}

	if err = c.validateWithDefaults(); err != nil {
		return nil, err
	}
	return c, nil
}

var regexMAC = regexp.MustCompile(`^[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}:[A-F0-9]{2}$`)
var regexTimezone = regexp.MustCompile(`^[a-zA-Z]+/[a-zA-Z]+$`)

func (c *Config) validateWithDefaults() error {
	c.Portal.MAC = strings.ToUpper(c.Portal.MAC)

	if c.Portal.Model == "" {
		return errors.New("empty model")
	}

	if c.Portal.SerialNumber == "" {
		return errors.New("empty serial number (sn)")
	}

	if c.Portal.DeviceID == "" {
		return errors.New("empty device_id")
	}

	if c.Portal.DeviceID2 == "" {
		return errors.New("empty device_id2")
	}

	// Signature can be empty and it's fine

	if !regexMAC.MatchString(c.Portal.MAC) {
		return errors.New("invalid MAC '" + c.Portal.MAC + "'")
	}

	/* Username and password fields are optional */

	if c.Portal.Location == "" {
		return errors.New("empty portal url")
	}
	// Accept bare hosts like "new.gprod.co" and keep as base URL.
	normURL, err := normalizePortalURL(c.Portal.Location)
	if err != nil {
		return err
	}
	c.Portal.Location = normURL

	if !regexTimezone.MatchString(c.Portal.TimeZone) {
		return errors.New("invalid timezone '" + c.Portal.TimeZone + "'")
	}

    // at least one functional service must be enabled.  The admin UI on its
    // own is not enough to provide IPTV streams or proxy functionality, so
    // ensure either the HLS or the Proxy service is turned on.  Admin may
    // optionally be enabled alongside those services.
    if !c.HLS.Enabled && !c.Proxy.Enabled && !c.Admin.Enabled {
        return errors.New("no services enabled")
    }

	if c.HLS.Enabled && c.HLS.Bind == "" {
		return errors.New("empty HLS bind")
	}

	if c.Proxy.Enabled && c.Proxy.Bind == "" {
		return errors.New("empty proxy bind")
	}

	if c.Proxy.Rewrite && !c.HLS.Enabled {
		return errors.New("HLS service must be enabled for 'proxy: rewrite'")
	}

	if c.Portal.Token == "" {
		c.Portal.Token = randomToken()
		log.Println("No token given, using random one:", c.Portal.Token)
	}
	
	if c.Portal.WatchDogTime == 1 {
		c.Portal.WatchDogTime = 2
		log.Println("Using Watchdog update interval = ", c.Portal.WatchDogTime)
	}

	return nil
}

// normalizePortalURL converts host-only or partial inputs into a valid URL
// with a scheme, but does not append any fixed path. The portal may redirect
// to its preferred endpoint (e.g., /stalker_portal/server/load.php).
func normalizePortalURL(raw string) (string, error) {
	uStr := strings.TrimSpace(raw)
	if uStr == "" {
		return "", errors.New("empty portal url")
	}
	if !strings.Contains(uStr, "://") {
		uStr = "https://" + uStr
	}
	u, err := url.Parse(uStr)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", errors.New("invalid portal url: missing host")
	}
	// Keep user-provided path/query as-is; do not force load.php.
	return u.String(), nil
}

func randomToken() string {
	allowlist := []rune("ABCDEF0123456789")
	b := make([]rune, 32)
	for i := range b {
		b[i] = allowlist[rand.Intn(len(allowlist))]
	}
	return string(b)
}
