package tunnel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Cloudflare consumer WARP API (wgcf-compatible). Undocumented; may break.
// Sources: ViRb3/wgcf OpenAPI (api v536), warp-reg official-warp-api.txt.
const (
	warpAPIBase = "https://api.cloudflareclient.com/v0a536"
	warpTOSURL  = "https://www.cloudflare.com/application/terms/"
	// Cloudflare WARP peer public key (stable across free WARP).
	warpPeerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
)

// WARPAccount is persisted device registration.
type WARPAccount struct {
	DeviceID   string `json:"device_id"`
	AccessToken string `json:"access_token"`
	PrivateKey string `json:"private_key"`
	License    string `json:"license,omitempty"`
	CreatedAt  string `json:"created_at"`
}

// WARPProfile is enough to build a selective WireGuard endpoint.
type WARPProfile struct {
	PrivateKey     string
	AddressIPv4    string
	AddressIPv6    string
	PeerPublicKey  string
	EndpointHost   string // host:port or host
	EndpointIPv4   string
	ClientID       string
	Reserved       [3]byte
}

type warpRegResponse struct {
	ID    string `json:"id"`
	Token string `json:"token"`
	Account struct {
		License string `json:"license"`
	} `json:"account"`
	Config warpConfigBody `json:"config"`
	WarpEnabled bool `json:"warp_enabled"`
}

type warpConfigBody struct {
	ClientID  string `json:"client_id"`
	Interface struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
	Peers []struct {
		PublicKey string       `json:"public_key"`
		Endpoint  warpEndpoint `json:"endpoint"`
	} `json:"peers"`
}

// warpEndpoint accepts both object {host,v4,v6} and bare string forms from CF API.
type warpEndpoint struct {
	Host string `json:"host"`
	V4   string `json:"v4"`
	V6   string `json:"v6"`
}

func (e *warpEndpoint) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		e.Host = s
		return nil
	}
	type alias warpEndpoint
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*e = warpEndpoint(a)
	return nil
}


// LoadOrRegisterWARP loads cached credentials or registers a new free WARP device.
func LoadOrRegisterWARP(dataDir string, client *http.Client) (*WARPAccount, *WARPProfile, error) {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(dataDir, "warp-account.json")

	if acc, err := loadWARPAccount(path); err == nil && acc.DeviceID != "" && acc.PrivateKey != "" {
		prof, err := fetchWARPProfile(client, acc)
		if err == nil {
			return acc, prof, nil
		}
		// Stale token → re-register below.
	}

	acc, prof, err := registerWARP(client)
	if err != nil {
		return nil, nil, err
	}
	if err := saveWARPAccount(path, acc); err != nil {
		return acc, prof, fmt.Errorf("warp: save account: %w", err)
	}
	return acc, prof, nil
}

func loadWARPAccount(path string) (*WARPAccount, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var acc WARPAccount
	if err := json.Unmarshal(b, &acc); err != nil {
		return nil, err
	}
	return &acc, nil
}

func saveWARPAccount(path string, acc *WARPAccount) error {
	b, err := json.MarshalIndent(acc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func registerWARP(client *http.Client) (*WARPAccount, *WARPProfile, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	tos := time.Now().UTC().Format(time.RFC3339)
	body := map[string]any{
		"install_id": "",
		"tos":        tos,
		"key":        kp.Public,
		"fcm_token":  "",
		"type":       "Android",
		"model":      "PC",
		"locale":     "en_US",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, warpAPIBase+"/reg", bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.30-536")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("warp register: %w", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("warp register HTTP %d: %s", resp.StatusCode, truncate(string(payload), 200))
	}
	var reg warpRegResponse
	if err := json.Unmarshal(payload, &reg); err != nil {
		return nil, nil, fmt.Errorf("warp register decode: %w", err)
	}
	if reg.ID == "" || reg.Token == "" {
		return nil, nil, fmt.Errorf("warp register: missing id/token")
	}

	acc := &WARPAccount{
		DeviceID:    reg.ID,
		AccessToken: reg.Token,
		PrivateKey:  kp.Private,
		License:     reg.Account.License,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	// Enable WARP on the device (best-effort; some API versions already enable).
	_ = enableWARP(client, acc)

	prof, err := profileFromConfig(acc.PrivateKey, reg.Config)
	if err != nil {
		// Fetch fresh config.
		prof, err = fetchWARPProfile(client, acc)
		if err != nil {
			return acc, nil, err
		}
	}
	return acc, prof, nil
}

func enableWARP(client *http.Client, acc *WARPAccount) error {
	raw, _ := json.Marshal(map[string]any{"warp_enabled": true})
	req, err := http.NewRequest(http.MethodPatch, warpAPIBase+"/reg/"+acc.DeviceID, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func fetchWARPProfile(client *http.Client, acc *WARPAccount) (*WARPProfile, error) {
	req, err := http.NewRequest(http.MethodGet, warpAPIBase+"/reg/"+acc.DeviceID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("warp config: %w", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("warp config HTTP %d: %s", resp.StatusCode, truncate(string(payload), 200))
	}
	var reg warpRegResponse
	if err := json.Unmarshal(payload, &reg); err != nil {
		return nil, err
	}
	return profileFromConfig(acc.PrivateKey, reg.Config)
}

func profileFromConfig(privateKey string, cfg warpConfigBody) (*WARPProfile, error) {
	if cfg.Interface.Addresses.V4 == "" || len(cfg.Peers) == 0 {
		return nil, fmt.Errorf("warp: incomplete config")
	}
	peer := cfg.Peers[0]
	pub := peer.PublicKey
	if pub == "" {
		pub = warpPeerPublicKey
	}
	reserved, err := ReservedFromClientID(cfg.ClientID)
	if err != nil {
		reserved = [3]byte{}
	}
	host := peer.Endpoint.Host
	if host == "" {
		host = "engage.cloudflareclient.com:2408"
	}
	return &WARPProfile{
		PrivateKey:    privateKey,
		AddressIPv4:   cfg.Interface.Addresses.V4,
		AddressIPv6:   cfg.Interface.Addresses.V6,
		PeerPublicKey: pub,
		EndpointHost:  host,
		EndpointIPv4:  peer.Endpoint.V4,
		ClientID:      cfg.ClientID,
		Reserved:      reserved,
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
