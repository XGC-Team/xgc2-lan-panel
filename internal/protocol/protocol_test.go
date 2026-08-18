package protocol

import (
	"strings"
	"testing"
)

func TestMarshalParseRoundTrip(t *testing.T) {
	in := Beacon{
		ID:           "abc123",
		Hostname:     "xavier",
		TSUnixMS:     1,
		DefaultIface: "wlan1",
		SSHUser:      "agilex",
		Users:        []string{"agilex"},
		Ifaces: []Iface{{
			Name:      "wlan1",
			MAC:       "aa:bb:cc:dd:ee:ff",
			Kind:      "wifi",
			Up:        true,
			Addrs:     []string{"192.168.100.40/24"},
			SSID:      "BIU_5G",
			Gateway:   "192.168.100.1",
			DNS:       []string{"192.168.100.1"},
			Metric:    50,
			IsDefault: true,
		}},
	}
	raw, err := MarshalBeacon(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "password") {
		t.Fatal("beacon must not mention password")
	}
	out, err := ParseBeacon(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != Kind || out.V != Version || out.ControlPort != ControlPort {
		t.Fatalf("defaults: %+v", out)
	}
	if out.ID != in.ID || out.Ifaces[0].SSID != "BIU_5G" {
		t.Fatalf("round trip: %+v", out)
	}
}

func TestParseRejectsOtherJSON(t *testing.T) {
	if _, err := ParseBeacon([]byte(`{"v":1,"kind":"nope","id":"a","hostname":"h"}`)); err == nil {
		t.Fatal("expected reject")
	}
}

func TestSolicitRoundTrip(t *testing.T) {
	raw, err := MarshalSolicit()
	if err != nil {
		t.Fatal(err)
	}
	if !IsSolicit(raw) {
		t.Fatalf("not recognized: %s", raw)
	}
	if IsSolicit([]byte(`{"v":1,"kind":"xgc2-lan-beacon"}`)) {
		t.Fatal("beacon must not look like solicit")
	}
}
