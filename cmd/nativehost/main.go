package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	appName       = "QuantumPasswordManager"
	maxMessageLen = 1 << 20 // 1MB
)

// Request represents a native messaging request from the browser extension.
type Request struct {
	Action            string `json:"action"`
	Domain            string `json:"domain,omitempty"`
	Username          string `json:"username,omitempty"`
	EncryptedPassword string `json:"encryptedPassword,omitempty"`
	// For updateCredential
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	URI      string `json:"uri,omitempty"`
	Notes    string `json:"notes,omitempty"`
	// For secureCopy
	Text string `json:"text,omitempty"`
}

// Response represents a native messaging response to the browser extension.
type Response struct {
	Status      string       `json:"status,omitempty"`
	Version     string       `json:"version,omitempty"`
	Credentials []Credential `json:"credentials,omitempty"`
	Locked      *bool        `json:"locked,omitempty"`
	VaultCount  *int         `json:"vaultCount,omitempty"`
	Error       string       `json:"error,omitempty"`
}

// Credential represents a single credential returned by the sidecar.
type Credential struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
	Name     string `json:"name"`
	URI      string `json:"uri"`
	Notes    string `json:"notes"`
	Matched  bool   `json:"matched"`
}

// SidecarClient communicates with the Electron Go sidecar via local HTTP.
type SidecarClient struct {
	httpClient *http.Client
	baseURL    string
	secret     string // shared secret for authenticating with extension endpoints
}

func main() {
	// Log to stderr so stdout is reserved for native messaging protocol
	logFile := configureLogging()
	if logFile != nil {
		defer func() { _ = logFile.Close() }()
	}

	log.Info().Msg("native messaging host started")

	client := newSidecarClient()

	for {
		msg, err := readMessage(os.Stdin)
		if err == io.EOF {
			log.Info().Msg("stdin closed, exiting")
			break
		}
		if err != nil {
			log.Error().Err(err).Msg("failed to read message")
			break
		}

		log.Debug().Str("action", msg.Action).Msg("received message")

		resp := handleMessage(client, msg)

		if err := writeMessage(os.Stdout, resp); err != nil {
			log.Error().Err(err).Msg("failed to write response")
			break
		}
	}
}

func configureLogging() *os.File {
	logDir := getAppDataDir()
	if err := os.MkdirAll(logDir, 0700); err != nil {
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
		return nil
	}

	logPath := filepath.Join(logDir, "nativehost.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
		return nil
	}

	log.Logger = zerolog.New(f).With().Timestamp().Logger()
	return f
}

func readMessage(r io.Reader) (*Request, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	if length > maxMessageLen {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	var msg Request
	if err := json.Unmarshal(buf, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

func writeMessage(w io.Writer, resp *Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, uint32(len(data))); err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

func handleMessage(client *SidecarClient, msg *Request) *Response {
	switch msg.Action {
	case "ping":
		return &Response{Status: "ok", Version: "1.0.0"}

	case "getCredentials":
		if msg.Domain == "" {
			return &Response{Error: "domain is required"}
		}
		return client.getCredentials(msg.Domain)

	case "saveCredential":
		if msg.Domain == "" || msg.Username == "" {
			return &Response{Error: "domain and username are required"}
		}
		return client.saveCredential(msg.Domain, msg.Username, msg.EncryptedPassword)

	case "getStatus":
		return client.getStatus()

	case "lock":
		return client.lock()

	case "updateCredential":
		if msg.ID == "" {
			return &Response{Error: "id is required"}
		}
		return client.updateCredential(msg.ID, msg.Name, msg.Username, msg.Password, msg.URI, msg.Notes)

	case "secureCopy":
		if msg.Text == "" {
			return &Response{Error: "text is required"}
		}
		return secureCopyToClipboard(msg.Text)

	case "openApp":
		return openDesktopApp()

	default:
		return &Response{Error: "unknown action: " + msg.Action}
	}
}

// --- Sidecar client ---

func newSidecarClient() *SidecarClient {
	return &SidecarClient{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// getSidecarURL reads the sidecar lockfile to discover the local HTTP port and secret.
func (c *SidecarClient) getSidecarURL() (string, error) {
	if c.baseURL != "" {
		return c.baseURL, nil
	}

	lockPath := filepath.Join(getAppDataDir(), "sidecar.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return "", fmt.Errorf("sidecar lockfile not found: %w", err)
	}

	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	port := strings.TrimSpace(lines[0])
	if port == "" {
		return "", fmt.Errorf("sidecar lockfile is empty")
	}

	if len(lines) > 1 {
		c.secret = strings.TrimSpace(lines[1])
	}

	c.baseURL = "http://127.0.0.1:" + port
	return c.baseURL, nil
}

func (c *SidecarClient) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	base, err := c.getSidecarURL()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		return nil, err
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c *SidecarClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	req, err := c.newRequest(method, path, body)
	if err != nil {
		return nil, err
	}
	return c.httpClient.Do(req)
}

func (c *SidecarClient) sidecarGet(path string) (*http.Response, error) {
	return c.doRequest("GET", path, nil)
}

func (c *SidecarClient) sidecarPost(path string, body io.Reader) (*http.Response, error) {
	return c.doRequest("POST", path, body)
}

func (c *SidecarClient) getCredentials(domain string) *Response {
	resp, err := c.sidecarGet("/extension/credentials?domain=" + domain)
	if err != nil {
		// Reset cached URL so next call re-reads lockfile
		c.baseURL = ""
		return &Response{Error: "Desktop app not running"}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return &Response{Error: fmt.Sprintf("sidecar returned %d", resp.StatusCode)}
	}

	var creds []Credential
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return &Response{Error: "failed to decode credentials"}
	}

	return &Response{Credentials: creds}
}

func (c *SidecarClient) saveCredential(domain, username, encryptedPassword string) *Response {
	payload, _ := json.Marshal(map[string]string{
		"domain":            domain,
		"username":          username,
		"encryptedPassword": encryptedPassword,
	})

	resp, err := c.sidecarPost("/extension/credentials", strings.NewReader(string(payload)))
	if err != nil {
		c.baseURL = ""
		return &Response{Error: "Desktop app not running"}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return &Response{Error: fmt.Sprintf("sidecar returned %d", resp.StatusCode)}
	}

	return &Response{Status: "saved"}
}

func (c *SidecarClient) updateCredential(id, name, username, password, uri, notes string) *Response {
	payload, _ := json.Marshal(map[string]string{
		"name":     name,
		"username": username,
		"password": password,
		"uri":      uri,
		"notes":    notes,
	})

	resp, err := c.doRequest("PUT", "/extension/credentials/"+id, strings.NewReader(string(payload)))
	if err != nil {
		c.baseURL = ""
		return &Response{Error: "Desktop app not running"}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return &Response{Error: fmt.Sprintf("sidecar returned %d", resp.StatusCode)}
	}

	return &Response{Status: "updated"}
}

func (c *SidecarClient) getStatus() *Response {
	resp, err := c.sidecarGet("/extension/status")
	if err != nil {
		c.baseURL = ""
		return &Response{Error: "Desktop app not running"}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return &Response{Error: fmt.Sprintf("sidecar returned %d", resp.StatusCode)}
	}

	var status struct {
		Locked     bool `json:"locked"`
		VaultCount int  `json:"vaultCount"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return &Response{Error: "failed to decode status"}
	}

	return &Response{
		Locked:     &status.Locked,
		VaultCount: &status.VaultCount,
	}
}

func (c *SidecarClient) lock() *Response {
	resp, err := c.sidecarPost("/extension/lock", nil)
	if err != nil {
		c.baseURL = ""
		return &Response{Error: "Desktop app not running"}
	}
	defer func() { _ = resp.Body.Close() }()

	return &Response{Status: "locked"}
}

// --- Secure clipboard ---

func secureCopyToClipboard(text string) *Response {
	if runtime.GOOS == "windows" {
		return secureCopyWindows(text)
	}
	// Fallback: use exec to copy (less secure — no history exclusion)
	return fallbackCopy(text)
}

func secureCopyWindows(text string) *Response {
	if err := secureCopyClipboardWindows(text); err != nil {
		log.Error().Err(err).Msg("Win32 clipboard copy failed, trying fallback")
		return fallbackCopy(text)
	}

	scheduleClipboardClear()
	return &Response{Status: "copied"}
}

func fallbackCopy(text string) *Response {
	switch runtime.GOOS {
	case "windows":
		// Use the same Win32 API path but without the exclude flag
		if err := secureCopyClipboardWindows(text); err != nil {
			return &Response{Error: "clipboard copy failed"}
		}
	case "darwin":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			return &Response{Error: "clipboard copy failed"}
		}
	default:
		cmd := exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			return &Response{Error: "clipboard copy failed"}
		}
	}

	scheduleClipboardClear()

	return &Response{Status: "copied"}
}

// --- Open desktop app ---

func openDesktopApp() *Response {
	appPath := findDesktopApp()
	if appPath == "" {
		return &Response{Error: "Desktop app not found"}
	}

	cmd := exec.Command(appPath) // #nosec G204 -- appPath is from findDesktopApp() which only returns validated paths
	cmd.Dir = filepath.Dir(appPath)
	if err := cmd.Start(); err != nil {
		return &Response{Error: "Failed to launch desktop app: " + err.Error()}
	}

	// Detach — don't wait for it
	go func() { _ = cmd.Wait() }()

	return &Response{Status: "ok"}
}

// scheduleClipboardClear spawns a detached process to clear the clipboard after 30 seconds.
// Must be a separate process because the native host exits immediately after responding.
func scheduleClipboardClear() {
	switch runtime.GOOS {
	case "windows":
		scheduleClipboardClearWindows()
	case "darwin":
		cmd := exec.Command("bash", "-c", "sleep 30 && echo -n '' | pbcopy") // #nosec G204
		_ = cmd.Start()
	default:
		cmd := exec.Command("bash", "-c", "sleep 30 && echo -n '' | xclip -selection clipboard") // #nosec G204
		_ = cmd.Start()
	}
}

func findDesktopApp() string {
	switch runtime.GOOS {
	case "windows":
		// Check common install locations
		candidates := []string{
			filepath.Join(os.Getenv("LOCALAPPDATA"), "quantum-password-manager", "Quantum Password Manager.exe"),
			filepath.Join(os.Getenv("PROGRAMFILES"), "Quantum Password Manager", "Quantum Password Manager.exe"),
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	case "darwin":
		candidates := []string{
			"/Applications/Quantum Password Manager.app/Contents/MacOS/Quantum Password Manager",
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	default: // linux
		// Try common paths
		candidates := []string{
			"/usr/bin/quantum-password-manager",
			"/opt/Quantum Password Manager/quantum-password-manager",
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// --- Platform-specific app data directory ---

func getAppDataDir() string {
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
		return filepath.Join(appData, appName)
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", appName)
	default: // linux
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", appName)
	}
}
