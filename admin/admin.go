package admin

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "strconv"

    "github.com/CrazeeGhost/stalkerhek/stalker"
    yaml "gopkg.in/yaml.v2"
)

// config holds a pointer to the in‑memory configuration.  It is updated
// directly when changes are submitted via the web interface.  Any
// modifications are persisted back to the YAML file specified by
// configPath.
var config *stalker.Config

// configPath stores the path to the YAML configuration file on disk.
var configPath string

// Start launches a lightweight administrative HTTP server that exposes
// endpoints for inspecting and editing the Stalker portal configuration and
// restarting the application.  The server runs until the application exits.
//
// Parameters:
//   c: pointer to the configuration object.  This is modified in place
//      when users submit changes via the web form.
//   path: filesystem path to the YAML configuration file.  Updated
//         configurations are written back to this file.
func Start(c *stalker.Config, path string) {
    config = c
    configPath = path

    // Register handlers.  We intentionally use absolute paths to
    // simplify linking.  The root and /config paths are mapped to the
    // same handler so that visiting the base URL serves the form.
    http.HandleFunc("/", handleConfig)
    http.HandleFunc("/config", handleConfig)
    http.HandleFunc("/restart", handleRestart)

    // Start the HTTP server.  Errors from ListenAndServe will stop
    // the admin goroutine but should not panic the entire process, so
    // we simply log them via fmt.Println.
    if err := http.ListenAndServe(c.Admin.Bind, nil); err != nil {
        fmt.Println("admin server error:", err)
    }
}

// handleConfig serves both GET and POST requests for the configuration
// interface.  A GET request renders the current configuration in a simple
// HTML form.  A POST request applies submitted values to the in‑memory
// configuration and writes the updated configuration back to the YAML
// file.  After saving, the user is presented with a confirmation and a
// link back to the form.
func handleConfig(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        // Render simple HTML form with current configuration values.
        fmt.Fprintf(w, "<html><body><h2>Stalker Portal Configuration</h2><form method=\"POST\" action=\"/config\">")
        fmt.Fprintf(w, "Model: <input name=\"model\" value=\"%s\"><br>", config.Portal.Model)
        fmt.Fprintf(w, "Serial Number: <input name=\"serial_number\" value=\"%s\"><br>", config.Portal.SerialNumber)
        fmt.Fprintf(w, "Device ID: <input name=\"device_id\" value=\"%s\"><br>", config.Portal.DeviceID)
        fmt.Fprintf(w, "Device ID2: <input name=\"device_id2\" value=\"%s\"><br>", config.Portal.DeviceID2)
        fmt.Fprintf(w, "Signature: <input name=\"signature\" value=\"%s\"><br>", config.Portal.Signature)
        fmt.Fprintf(w, "MAC: <input name=\"mac\" value=\"%s\"><br>", config.Portal.MAC)
        fmt.Fprintf(w, "Username: <input name=\"username\" value=\"%s\"><br>", config.Portal.Username)
        fmt.Fprintf(w, "Password: <input name=\"password\" type=\"password\" value=\"%s\"><br>", config.Portal.Password)
        fmt.Fprintf(w, "URL: <input name=\"url\" value=\"%s\"><br>", config.Portal.Location)
        fmt.Fprintf(w, "Time Zone: <input name=\"time_zone\" value=\"%s\"><br>", config.Portal.TimeZone)
        fmt.Fprintf(w, "Token: <input name=\"token\" value=\"%s\"><br>", config.Portal.Token)
        fmt.Fprintf(w, "Watchdog Interval: <input name=\"watchdog\" value=\"%d\"><br>", config.Portal.WatchDogTime)
        // Checkbox for DeviceIdAuth
        checked := ""
        if config.Portal.DeviceIdAuth {
            checked = "checked"
        }
        fmt.Fprintf(w, "Device ID Auth: <input type=\"checkbox\" name=\"device_id_auth\" %s><br>", checked)
        fmt.Fprintf(w, "<input type=\"submit\" value=\"Save\"></form>")
        // Separate form for restart button
        fmt.Fprintf(w, "<form method=\"POST\" action=\"/restart\"><input type=\"submit\" value=\"Restart\"></form>")
        fmt.Fprintf(w, "</body></html>")
    case http.MethodPost:
        // Apply posted values to configuration
        if err := r.ParseForm(); err != nil {
            http.Error(w, "bad request", http.StatusBadRequest)
            return
        }
        // Update portal fields from form values
        config.Portal.Model = r.FormValue("model")
        config.Portal.SerialNumber = r.FormValue("serial_number")
        config.Portal.DeviceID = r.FormValue("device_id")
        config.Portal.DeviceID2 = r.FormValue("device_id2")
        config.Portal.Signature = r.FormValue("signature")
        config.Portal.MAC = r.FormValue("mac")
        config.Portal.Username = r.FormValue("username")
        config.Portal.Password = r.FormValue("password")
        config.Portal.Location = r.FormValue("url")
        config.Portal.TimeZone = r.FormValue("time_zone")
        config.Portal.Token = r.FormValue("token")
        // Parse watchdog interval from string
        if wdStr := r.FormValue("watchdog"); wdStr != "" {
            if wd, err := strconv.Atoi(wdStr); err == nil {
                config.Portal.WatchDogTime = wd
            }
        }
        // Checkbox returns "on" when checked
        config.Portal.DeviceIdAuth = r.FormValue("device_id_auth") == "on"
        // Marshal updated configuration back to YAML and write to file
        if out, err := yaml.Marshal(config); err == nil {
            ioutil.WriteFile(configPath, out, 0644)
        }
        fmt.Fprintf(w, "<html><body>Configuration updated.<br><a href=\"/\">Back</a></body></html>")
    default:
        // Only GET and POST are supported
        w.WriteHeader(http.StatusMethodNotAllowed)
    }
}

// handleRestart triggers a graceful restart of the application.  When the
// restart form is submitted the handler writes a simple message to the
// response before calling os.Exit(0).  The caller (e.g. systemd) is
// responsible for bringing the service back up.
func handleRestart(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }
    // Inform the user that the restart is in progress.  We flush the
    // response so the browser receives it before the process exits.
    fmt.Fprintf(w, "<html><body>Restarting...</body></html>")
    if flusher, ok := w.(http.Flusher); ok {
        flusher.Flush()
    }
    // Terminate the process.  External process manager should restart us.
    os.Exit(0)
}