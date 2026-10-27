package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Consumer WARP WireGuard ingress and its documented fallback ports:
// https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/
var (
	warpEndpointHosts = []string{"162.159.192.1", "162.159.193.10", "162.159.192.7", "162.159.193.4"}
	warpEndpointPorts = []int{2408, 500, 1701, 4500}
)

const (
	warpPreflightBudget = 40 * time.Second
	warpPreflightPort   = 18130
	warpEndpointFile    = "warp-endpoint.json"
)

// EndpointTrial is one WARP ingress attempt. Only Cloudflare addresses appear.
type EndpointTrial struct {
	Endpoint string    `json:"endpoint"`
	Class    FailClass `json:"class"`
	Stage    string    `json:"stage,omitempty"`
}

// WARPEndpointCandidates puts the remembered endpoint first, then the profile's
// own address, then every documented host and port.
func WARPEndpointCandidates(profile *WARPProfile, remembered string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(endpoint string) {
		if endpoint == "" || seen[endpoint] {
			return
		}
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return
		}
		seen[endpoint] = true
		out = append(out, endpoint)
	}
	add(remembered)
	hosts := append([]string(nil), warpEndpointHosts...)
	if profile != nil && profile.EndpointIPv4 != "" {
		host, _ := splitHostPort(profile.EndpointIPv4, 2408)
		hosts = append([]string{host}, hosts...)
	}
	for _, port := range warpEndpointPorts {
		for _, host := range hosts {
			add(net.JoinHostPort(host, strconv.Itoa(port)))
		}
	}
	return out
}

// PrepareWARP loads or registers the device over the physical interface. It
// is called only when a group actually needs the tunnel.
func PrepareWARP(ctx context.Context, cfg Config) (*WARPProfile, error) {
	dataDir, err := resolveDataDir(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	client := newBootstrapHTTPClient(cfg)
	defer client.CloseIdleConnections()
	_, profile, err := loadOrRegisterWARP(ctx, dataDir, client)
	return profile, err
}

// PreflightWARP tries endpoints through private TUN-free SOCKS listeners and
// returns a profile pinned to the first one that passes the control quorum.
func PreflightWARP(ctx context.Context, cfg Config, profile *WARPProfile, scope string) (*WARPProfile, []EndpointTrial, error) {
	if profile == nil {
		return nil, nil, fmt.Errorf("warp profile required")
	}
	if err := normalizeControls(&cfg); err != nil {
		return nil, nil, err
	}
	dataDir, err := resolveDataDir(cfg.DataDir)
	if err != nil {
		return nil, nil, err
	}
	cfg.DataDir = dataDir
	candidates := WARPEndpointCandidates(profile, rememberedEndpoint(dataDir, scope))
	budget, cancel := context.WithTimeout(ctx, warpPreflightBudget)
	defer cancel()
	type result struct {
		index   int
		trial   EndpointTrial
		profile *WARPProfile
	}
	jobs := make(chan int)
	results := make(chan result, len(candidates))
	var workers sync.WaitGroup
	for w := 0; w < 3; w++ {
		workers.Go(func() {
			for i := range jobs {
				pinned := *profile
				pinned.EndpointIPv4 = candidates[i]
				trialCfg := cfg
				trialCfg.Selective, trialCfg.NetworkMode, trialCfg.providerOnly = false, true, true
				trialCfg.EnableTUN, trialCfg.WARPProfile, trialCfg.NetworkRoutes = false, &pinned, nil
				trialCfg.ListenPort, trialCfg.ProbeTimeout = warpPreflightPort+i, 5*time.Second
				attempt, stop := context.WithTimeout(budget, 10*time.Second)
				trialCfg.Context, trialCfg.startupContext = attempt, attempt
				s, ok, class, err := startOne(trialCfg, providerAttempt{ID: ProviderWARP})
				stop()
				trial := EndpointTrial{Endpoint: candidates[i], Class: class}
				if s != nil {
					_ = s.Close()
				}
				if ok {
					trial.Class = FailOK
					results <- result{i, trial, &pinned}
					cancel()
					return
				}
				if f := providerFailure(s, ProviderWARP, class, err); f.Stage != "" {
					trial.Stage = f.Stage
				}
				results <- result{i, trial, nil}
			}
		})
	}
	go func() {
		defer close(jobs)
		for i := range candidates {
			select {
			case <-budget.Done():
				return
			case jobs <- i:
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	var trials []EndpointTrial
	var winner *WARPProfile
	for r := range results {
		trials = append(trials, r.trial)
		if r.profile != nil && winner == nil {
			winner = r.profile
		}
	}
	if winner == nil {
		return nil, trials, fmt.Errorf("no WARP endpoint passed the control quorum")
	}
	rememberEndpoint(dataDir, scope, winner.EndpointIPv4)
	return winner, trials, nil
}

func rememberedEndpoint(dataDir, scope string) string {
	raw, err := os.ReadFile(filepath.Join(dataDir, warpEndpointFile))
	if err != nil {
		return ""
	}
	var saved map[string]string
	if json.Unmarshal(raw, &saved) != nil {
		return ""
	}
	return saved[scope]
}

func rememberEndpoint(dataDir, scope, endpoint string) {
	path := filepath.Join(dataDir, warpEndpointFile)
	saved := map[string]string{}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &saved)
	}
	if len(saved) > 32 {
		saved = map[string]string{}
	}
	saved[scope] = endpoint
	if raw, err := json.Marshal(saved); err == nil {
		_ = os.WriteFile(path, raw, 0o600)
	}
}
