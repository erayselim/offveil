package ipc

import (
	"encoding/json"
	"net"
	"testing"
)

type pingHandler struct{}

func (pingHandler) Handle(method string, params map[string]any) (any, *RPCError) {
	if method == "ping" || method == "health" {
		return PingResult{Version: "test", ContractsVersion: 1, Service: "offveil-core"}, nil
	}
	return nil, &RPCError{Code: CodeBadRequest, Message: "unknown method"}
}

func TestServeConnPing(t *testing.T) {
	srv := NewServer(pingHandler{})
	c1, c2 := net.Pipe()
	defer c1.Close()
	go srv.serveConn(c2)

	enc := json.NewEncoder(c1)
	dec := json.NewDecoder(c1)
	if err := enc.Encode(Request{ID: "1", Method: "ping"}); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("resp=%+v", resp)
	}
	raw, _ := json.Marshal(resp.Result)
	if string(raw) == "" || string(raw) == "null" {
		t.Fatalf("empty result: %s", raw)
	}
}

func TestEndpoint(t *testing.T) {
	if Endpoint() == "" {
		t.Fatal("empty endpoint")
	}
}
