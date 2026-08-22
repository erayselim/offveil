package tunnel

import (
	"encoding/json"
	"testing"
)

func TestWarpEndpointUnmarshalObject(t *testing.T) {
	var e warpEndpoint
	raw := []byte(`{"host":"engage.cloudflareclient.com:2408","v4":"162.159.192.1:2408","v6":"[2606:4700:d0::a29f:c001]:2408"}`)
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.Host != "engage.cloudflareclient.com:2408" || e.V4 == "" {
		t.Fatalf("%+v", e)
	}
}

func TestWarpEndpointUnmarshalString(t *testing.T) {
	var e warpEndpoint
	raw := []byte(`"engage.cloudflareclient.com:2408"`)
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.Host != "engage.cloudflareclient.com:2408" {
		t.Fatalf("%+v", e)
	}
}

func TestWarpConfigPeersEndpointString(t *testing.T) {
	raw := []byte(`{
		"client_id": "q1XNAQ==",
		"interface": {"addresses": {"v4": "172.16.0.2/32", "v6": ""}},
		"peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "endpoint": "engage.cloudflareclient.com:2408"}]
	}`)
	var cfg warpConfigBody
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	prof, err := profileFromConfig("priv", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if prof.EndpointHost != "engage.cloudflareclient.com:2408" {
		t.Fatalf("host=%q", prof.EndpointHost)
	}
}
