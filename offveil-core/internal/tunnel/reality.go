package tunnel

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// RealityCredentials is optional self-hosted VLESS+Reality.
// Loaded from OFFVEIL_REALITY_JSON or dataDir/reality.json - never asked as UI preset.
type RealityCredentials struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	UUID       string `json:"uuid"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
	ServerName string `json:"server_name"` // SNI / camouflage
	Flow       string `json:"flow,omitempty"`
}

// LoadRealityCredentials reads Reality from cfg override, env, or dataDir file.
func LoadRealityCredentials(explicit *RealityCredentials, dataDir string) (*RealityCredentials, error) {
	if explicit != nil && explicit.Server != "" && explicit.UUID != "" && explicit.PublicKey != "" {
		c := *explicit
		normalizeReality(&c)
		return &c, nil
	}
	if raw := strings.TrimSpace(os.Getenv("OFFVEIL_REALITY_JSON")); raw != "" {
		var c RealityCredentials
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return nil, fmt.Errorf("OFFVEIL_REALITY_JSON: %w", err)
		}
		normalizeReality(&c)
		if c.Server == "" || c.UUID == "" {
			return nil, fmt.Errorf("OFFVEIL_REALITY_JSON incomplete")
		}
		return &c, nil
	}
	// Flat env fallback (optional ops wiring - not a user preset).
	if server := strings.TrimSpace(os.Getenv("OFFVEIL_REALITY_SERVER")); server != "" {
		c := RealityCredentials{
			Server:     server,
			UUID:       os.Getenv("OFFVEIL_REALITY_UUID"),
			PublicKey:  os.Getenv("OFFVEIL_REALITY_PUBLIC_KEY"),
			ShortID:    os.Getenv("OFFVEIL_REALITY_SHORT_ID"),
			ServerName: os.Getenv("OFFVEIL_REALITY_SNI"),
			Flow:       os.Getenv("OFFVEIL_REALITY_FLOW"),
		}
		if p := os.Getenv("OFFVEIL_REALITY_PORT"); p != "" {
			n, _ := strconv.Atoi(p)
			c.ServerPort = n
		}
		normalizeReality(&c)
		if c.UUID == "" || c.PublicKey == "" {
			return nil, fmt.Errorf("reality env incomplete")
		}
		return &c, nil
	}
	if dataDir != "" {
		path := dataDir + string(os.PathSeparator) + "reality.json"
		b, err := os.ReadFile(path)
		if err == nil {
			var c RealityCredentials
			if err := json.Unmarshal(b, &c); err != nil {
				return nil, fmt.Errorf("reality.json: %w", err)
			}
			normalizeReality(&c)
			if c.Server != "" && c.UUID != "" {
				return &c, nil
			}
		}
	}
	return nil, fmt.Errorf("reality credentials not configured")
}

func normalizeReality(c *RealityCredentials) {
	if c.ServerPort == 0 {
		c.ServerPort = 443
	}
	if c.Flow == "" {
		c.Flow = "xtls-rprx-vision"
	}
	if c.ServerName == "" {
		c.ServerName = "www.cloudflare.com"
	}
}

// providerAttempt is one ordered failover candidate.
type providerAttempt struct {
	ID      ProviderID
	Reality *RealityCredentials
}

// failoverEnabled returns whether WARP↔Reality auto-failover is on (default true).
func failoverEnabled(cfg Config) bool {
	if cfg.Failover == nil {
		return true
	}
	return *cfg.Failover
}

// ProviderOrder returns the try-list for WARP ↔ Reality failover.
// PreferReality / available Reality → Reality first, then WARP; else WARP then Reality (if creds).
func ProviderOrder(cfg Config, dataDir string) []providerAttempt {
	reality, rerr := LoadRealityCredentials(cfg.Reality, dataDir)
	hasReality := rerr == nil && reality != nil

	if cfg.PreferReality {
		if !hasReality {
			return []providerAttempt{{ID: ProviderWARP}}
		}
		out := []providerAttempt{{ID: ProviderReality, Reality: reality}}
		if failoverEnabled(cfg) {
			out = append(out, providerAttempt{ID: ProviderWARP})
		}
		return out
	}

	// Default: Reality when configured (TR WARP fragile); else WARP-first with Reality yedek.
	if hasReality {
		out := []providerAttempt{{ID: ProviderReality, Reality: reality}}
		if failoverEnabled(cfg) {
			out = append(out, providerAttempt{ID: ProviderWARP})
		}
		return out
	}
	return []providerAttempt{{ID: ProviderWARP}}
}

// SelectProvider chooses the primary provider (first in ProviderOrder).
func SelectProvider(cfg Config, dataDir string) (ProviderID, *RealityCredentials, error) {
	order := ProviderOrder(cfg, dataDir)
	if len(order) == 0 {
		return ProviderWARP, nil, nil
	}
	if cfg.PreferReality && order[0].ID != ProviderReality {
		return "", nil, fmt.Errorf("prefer reality: credentials not configured")
	}
	return order[0].ID, order[0].Reality, nil
}
