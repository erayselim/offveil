package engine_test

import (
	"archive/zip"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/capture"
	offdns "github.com/erayselim/offveil/offveil-core/internal/dns"
	"github.com/erayselim/offveil/offveil-core/internal/engine"
)

func TestStatusAndDiagnosticsDuringBlockedStart(t *testing.T) {
	t.Setenv("OFFVEIL_DIAG_DIR", t.TempDir())
	eng := newTestEngine(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	eng.WithCaptureStart(func(capture.Config) (capture.Session, error) {
		close(entered)
		<-release
		return nil, errors.New("capture failed for test")
	})
	go func() {
		defer close(done)
		_, _ = eng.Start("auto")
	}()
	releaseStart := sync.OnceFunc(func() { close(release); <-done })
	defer releaseStart()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("start never reached capture")
	}

	checked := make(chan struct{})
	go func() {
		defer close(checked)
		st := eng.Status()
		if st.State != engine.StateStarting || st.Protection {
			t.Errorf("startup status: %+v", st)
		}
		// Callers cannot mutate the published copy used by subsequent requests.
		st.State = "mutated"
		if eng.Status().State != engine.StateStarting {
			t.Error("snapshot was mutated by status caller")
		}
		meta, err := eng.Diagnostics()
		if err != nil {
			t.Error(err)
			return
		}
		zr, err := zip.OpenReader(meta.Path)
		if err != nil {
			t.Error(err)
			return
		}
		defer zr.Close()
		for _, f := range zr.File {
			if f.Name != "diagnostics.json" {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				t.Error(err)
				return
			}
			raw, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				t.Error(err)
				return
			}
			if !strings.Contains(string(raw), "startup_stage=capture") ||
				!strings.Contains(string(raw), `"state": "starting"`) {
				t.Errorf("missing startup context: %s", raw)
			}
			return
		}
		t.Error("missing diagnostics.json")
	}()
	select {
	case <-checked:
	case <-time.After(4 * time.Second):
		t.Error("status/diagnostics waited for blocked startup")
		// Allow the blocked reader to finish before test cleanup.
		releaseStart()
		<-checked
	}
}

func TestDNSObserverDoesNotWaitForStartupLock(t *testing.T) {
	eng := newTestEngine(t)
	eng.WithDNSStart(func(cfg offdns.Config) (offdns.Session, error) {
		// A system DNS request may arrive as soon as networksetup switches to
		// the stub, while Start still owns the engine lock.
		returned := make(chan struct{})
		go func() { cfg.OnQuery("requested.example.test"); close(returned) }()
		select {
		case <-returned:
		case <-time.After(time.Second):
			t.Error("DNS observer blocked on startup")
		}
		return nil, errors.New("stop after DNS observer check")
	})
	if _, err := eng.Start("auto"); err == nil {
		t.Fatal("expected injected DNS failure")
	}
	if eng.Status().State != engine.StateStopped {
		t.Fatal("failed startup left a stale starting snapshot")
	}
}
