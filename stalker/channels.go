package stalker

import (
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"strings"
)

// Channel stores information about channel in Stalker portal. This is not a real TV channel representation, but details on how to retrieve a working channel's URL.
type Channel struct {
	Title    string             // Used for Proxy service to generate fake response to new URL request
	CMD      string             // channel's identifier in Stalker portal
	LogoLink string             // Link to logo
	Portal   *Portal            // Reference to portal from where this channel is taken from
	GenreID  string             // Stores genre ID (category ID)
	Genres   *map[string]string // Stores mappings for genre ID -> genre title

	CMD_ID    string // Used for Proxy service to generate fake response to new URL request
	CMD_CH_ID string // Used for Proxy service to generate fake response to new URL request
}

// NewLink retrieves a link to the working channel. Retrieved link can be played in VLC or Kodi, but expires very soon if not being constantly opened (used).
func (c *Channel) NewLink(retry bool) (string, error) {
	type tmpStruct struct {
		Js struct {
			Cmd string `json:"cmd"`
		} `json:"js"`
	}
	var tmp tmpStruct

	link := c.Portal.Location + "?action=create_link&type=itv&cmd=" + url.PathEscape(c.CMD) + "&JsHttpRequest=1-xml"
	content, err := c.Portal.httpRequest(link)
	if err != nil {
		return "", err
	}

	if err := json.Unmarshal(content, &tmp); err != nil {
		// It could be that session has expired and user need to authenticate again.
		log.Println("Failed to retrieve new link...")
		if !retry && c.Portal.Username != "" && c.Portal.Password != "" {
			log.Println("Attempting to re-authenticate via username and password ...")
			if err2 := c.Portal.authenticate(); err2 != nil {
				log.Println("Reauthentication failed...")
				return "", err
			}
			log.Println("Reauthentication success, retrying to retrieve new link...")
			return c.NewLink(true)
		} else if !retry && c.Portal.DeviceID != "" && c.Portal.DeviceID2 != "" {
			log.Println("Attempting to re-authenticate via Device Ids ...")
			if err2 := c.Portal.authenticateWithDeviceIDs(); err2 != nil {
				log.Println("Reauthentication failed...")
				return "", err
			}
			log.Println("Reauthentication success, retrying to retrieve new link...")
			return c.NewLink(true)
		}
		return "", err
	}

	if strings.TrimSpace(tmp.Js.Cmd) == "" {
		return "", errors.New("empty cmd in create_link response")
	}

	strs := strings.Split(tmp.Js.Cmd, " ")
	return strs[len(strs)-1], nil
}

// Logo returns full link to channel's logo
func (c *Channel) Logo() string {
	if c.LogoLink == "" {
		return ""
	}
	// Derive portal root. If /stalker_portal/ exists in path, keep up to it;
	// otherwise default to /stalker_portal/ at the host root.
	u, err := url.Parse(c.Portal.Location)
	if err != nil || u.Host == "" {
		// Fallback: append a safe default path
		base := strings.TrimRight(c.Portal.Location, "/")
		return base + "/stalker_portal/misc/logos/320/" + c.LogoLink
	}
	rootPath := "/stalker_portal/"
	if idx := strings.Index(u.Path, "/stalker_portal/"); idx != -1 {
		rootPath = u.Path[:idx+len("/stalker_portal/")]
	}
	u.Path = strings.TrimRight(rootPath, "/") + "/misc/logos/320/" + c.LogoLink
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// Genre returns a genre title
func (c *Channel) Genre() string {
	g, ok := (*c.Genres)[c.GenreID]
	if !ok {
		g = "Other"
	}
	return strings.Title(g)
}

// RetrieveChannels retrieves all TV channels from stalker portal.
func (p *Portal) RetrieveChannels() (map[string]*Channel, error) {
	type tmpStruct struct {
		Js struct {
			Data []struct {
				Name    string `json:"name"`        // Title of channel
				Cmd     string `json:"cmd"`         // Some sort of URL used to request channel real URL
				Logo    string `json:"logo"`        // Link to logo
				GenreID string `json:"tv_genre_id"` // Genre ID
				CMDs    []struct {
					ID    string `json:"id"`    // Used for Proxy service to generate fake response to new URL request
					CH_ID string `json:"ch_id"` // Used for Proxy service to generate fake response to new URL request
				} `json:"cmds"`
			} `json:"data"`
		} `json:"js"`
	}
	var tmp tmpStruct

	content, err := p.httpRequest(p.Location + "?type=itv&action=get_all_channels&JsHttpRequest=1-xml")
	if err != nil {
		return nil, err
	}

	// Dump json output to file
	//ioutil.WriteFile("/tmp/dumpedchannels.json", content, 0644)

	if err := json.Unmarshal(content, &tmp); err != nil {
		log.Fatalln(string(content))
	}

	genres, err := p.getGenres()
	if err != nil {
		return nil, err
	}

	// Build channels list and return
	channels := make(map[string]*Channel, len(tmp.Js.Data))
	for _, v := range tmp.Js.Data {
		cmdID := ""
		chID := ""
		if len(v.CMDs) > 0 {
			cmdID = v.CMDs[0].ID
			chID = v.CMDs[0].CH_ID
		}
		channels[v.Name] = &Channel{
			Title:     v.Name,
			CMD:       v.Cmd,
			LogoLink:  v.Logo,
			Portal:    p,
			GenreID:   v.GenreID,
			Genres:    &genres,
			CMD_CH_ID: cmdID,
			CMD_ID:    chID,
		}
	}

	return channels, nil
}

func (p *Portal) getGenres() (map[string]string, error) {
	type tmpStruct struct {
		Js []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"js"`
	}
	var tmp tmpStruct

	content, err := p.httpRequest(p.Location + "?action=get_genres&type=itv&JsHttpRequest=1-xml")
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(content, &tmp); err != nil {
		log.Fatalln(string(content))
	}

	genres := make(map[string]string, len(tmp.Js))
	for _, el := range tmp.Js {
		genres[el.ID] = el.Title
	}

	return genres, nil
}
