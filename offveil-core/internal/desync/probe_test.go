package desync

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestClassifyDialErr(t *testing.T) {
	cases := []struct {
		err  error
		want FailClass
	}{
		{context.DeadlineExceeded, FailTimeout},
		{io.EOF, FailReset},
		{io.ErrUnexpectedEOF, FailReset},
		{errors.New("read: connection reset by peer"), FailReset},
		{errors.New("wsarecv: An existing connection was forcibly closed"), FailReset},
		{&tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, FailSSLErr},
		{errors.New("tls: handshake failure"), FailSSLErr},
		{&net.OpError{Op: "read", Err: timeoutErr{}}, FailTimeout},
	}
	for _, tc := range cases {
		got := classifyDialErr(tc.err)
		if got != tc.want {
			t.Fatalf("classify(%v)=%s want %s", tc.err, got, tc.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestFakeSession(t *testing.T) {
	f := NewFakeSession(Info{})
	if !f.Info().Up {
		t.Fatal("expected up")
	}
	sig := f.ProbeTLS("discord.com")
	if sig.Class != FailOK {
		t.Fatalf("probe=%v", sig)
	}
	_ = f.Close()
	if !f.Closed() {
		t.Fatal("expected closed")
	}
}

func TestWaitSOCKSTimeout(t *testing.T) {
	err := waitSOCKS("127.0.0.1:1", 150*time.Millisecond)
	if err == nil {
		t.Fatal("expected error")
	}
}
