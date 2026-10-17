package tunnel

import "github.com/erayselim/offveil/offveil-core/internal/ruleset"

func defaultProtectedDomains() []string {
	return ruleset.MustLoadEmbedded().Doc.ProtectedDomains()
}

// Raw TUN UDP has no hostname. Match supported apps without depending on DNS cache state.
func applicationUDPRules(p BuildParams, quic bool) []any {
	var out []any
	for _, app := range []struct {
		domain string
		names  []string
		path   string
	}{
		{"discord.com", []string{"Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe", "Discord", "Discord PTB", "Discord Canary"}, `(?i)/Discord( PTB| Canary| Development)?\.app/Contents/`},
		{"imvu.com", []string{"IMVUClient.exe", "IMVU.exe", "IMVU", "IMVU Desktop"}, `(?i)/IMVU( Desktop)?\.app/Contents/`},
	} {
		if IsDirectHost(app.domain, p.DirectDomains) {
			continue
		}
		outbound := ""
		if IsDirectHost(app.domain, p.TunnelDomains) && p.Provider != ProviderDesync {
			outbound = "tunnel"
		} else if IsDirectHost(app.domain, p.SpecialDomains) {
			outbound = "desync"
		}
		if outbound == "" {
			continue
		}
		for _, match := range []map[string]any{
			{"process_name": app.names},
			{"process_path_regex": []string{app.path}},
		} {
			match["network"] = "udp"
			if quic {
				match["protocol"], match["action"], match["method"] = "quic", "reject", "drop"
			} else {
				match["outbound"] = outbound
			}
			out = append(out, match)
		}
	}
	return out
}
