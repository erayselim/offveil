package dns

import (
	"strings"
	"testing"
)

func TestPrivateRelayFromScutil(t *testing.T) {
	off := `resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 14 (en0)
  flags    : Request A records
`
	if PrivateRelayFromScutil(off) {
		t.Fatal("plain DHCP resolver is not Private Relay")
	}
	on := `resolver #1
  nameserver[0] : 127.0.0.1
resolver #8
  domain   : mask.icloud.com
  nameserver[0] : 17.248.1.1
`
	if !PrivateRelayFromScutil(on) {
		t.Fatal("mask.icloud.com must count as Private Relay")
	}
	if !PrivateRelayFromScutil("nameserver[0] : doh.dns.apple.com") {
		t.Fatal("doh.dns.apple.com must count")
	}
}

func TestRelayDiagNoteNoDisable(t *testing.T) {
	on := RelayDiagNote(true)
	if !strings.Contains(on, "icloud_private_relay: on") || !strings.Contains(on, "does not disable") {
		t.Fatalf("note=%q", on)
	}
	if RelayDiagNote(false) != "icloud_private_relay: off" {
		t.Fatalf("off=%q", RelayDiagNote(false))
	}
	if PrivateRelayHintTR != "iCloud Özel Aktarma kapalı olsun." {
		t.Fatalf("tr=%q", PrivateRelayHintTR)
	}
	if PrivateRelayHintEN != "Keep iCloud Private Relay off." {
		t.Fatalf("en=%q", PrivateRelayHintEN)
	}
}
