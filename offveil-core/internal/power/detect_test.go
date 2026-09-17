package power_test

import (
	"testing"
	"time"

	"github.com/erayselim/offveil/offveil-core/internal/power"
)

func TestSleptThrough(t *testing.T) {
	interval := 2 * time.Second
	prev := time.Date(2026, 9, 18, 1, 0, 0, 0, time.UTC)
	if power.SleptThrough(prev, prev.Add(2*time.Second), interval) {
		t.Fatal("normal tick")
	}
	if !power.SleptThrough(prev, prev.Add(30*time.Second), interval) {
		t.Fatal("sleep freeze")
	}
	if power.SleptThrough(time.Time{}, prev, interval) {
		t.Fatal("zero prev")
	}
}

func TestNewerWake(t *testing.T) {
	a := time.Unix(100, 0)
	b := time.Unix(200, 0)
	if !power.NewerWake(a, b) {
		t.Fatal("waketime advanced")
	}
	if power.NewerWake(b, a) {
		t.Fatal("older")
	}
	if power.NewerWake(time.Time{}, b) {
		t.Fatal("zero prev")
	}
}
