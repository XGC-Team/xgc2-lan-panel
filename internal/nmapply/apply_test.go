package nmapply

import (
	"strings"
	"testing"

	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
)

func TestBuildPlanWifiStaticDefault(t *testing.T) {
	plan, err := BuildPlan(protocol.ApplyRequest{
		Iface:       "wlan1",
		SSID:        "BIU_5G",
		Password:    "secret-pass",
		Address:     "192.168.100.40/24",
		Gateway:     "192.168.100.1",
		DNS:         []string{"192.168.100.1"},
		MakeDefault: true,
	}, "wifi", map[string]string{"wlan0": "JG", "wlan1": "old"})
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, c := range plan.Commands {
		s := c.String()
		if strings.Contains(s, "secret-pass") {
			t.Fatalf("password leaked in %q", s)
		}
		joined += s + "\n"
	}
	if !strings.Contains(joined, "ssid BIU_5G") {
		t.Fatalf("missing ssid: %s", joined)
	}
	if !strings.Contains(joined, "connection.interface-name wlan1") {
		t.Fatalf("must pin iface: %s", joined)
	}
	if !strings.Contains(joined, "ipv4.addresses 192.168.100.40/24") {
		t.Fatalf("missing static: %s", joined)
	}
	if !strings.Contains(joined, "ipv4.route-metric 50") {
		t.Fatalf("missing preferred metric: %s", joined)
	}
	if !strings.Contains(joined, "connection modify JG ipv4.route-metric 20600") {
		t.Fatalf("must demote the other NIC: %s", joined)
	}
	if !strings.Contains(joined, "***") {
		t.Fatal("expected redacted psk")
	}
}

func TestBuildPlanDefaultOnlyRequiresActive(t *testing.T) {
	_, err := BuildPlan(protocol.ApplyRequest{Iface: "wlan1", MakeDefault: true}, "wifi", map[string]string{})
	if err == nil {
		t.Fatal("expected error")
	}
	plan, err := BuildPlan(protocol.ApplyRequest{Iface: "wlan1", MakeDefault: true}, "wifi", map[string]string{"wlan1": "BIU_5G-usb"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan.Commands[0].String(), "connection add") {
		t.Fatal("default-only must not create a new wifi")
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(protocol.ApplyRequest{Iface: "wlan1;rm", SSID: "x"}); err == nil {
		t.Fatal("expected invalid iface")
	}
	if err := Validate(protocol.ApplyRequest{Iface: "wlan1", Address: "192.168.100.40"}); err == nil {
		t.Fatal("expected cidr")
	}
}

func TestParseActiveConnections(t *testing.T) {
	got := ParseActiveConnections("BIU_5G-usb:wlan1:wifi\nJG:wlan0:wifi\n")
	if got["wlan1"] != "BIU_5G-usb" || got["wlan0"] != "JG" {
		t.Fatalf("%v", got)
	}
}

func TestRunSkipsMissingDelete(t *testing.T) {
	plan := Plan{Commands: []Command{
		{Args: []string{"connection", "delete", "xgc2-wlan1"}},
		{Args: []string{"connection", "up", "xgc2-wlan1"}},
	}}
	n := 0
	err := Run(func(args []string) (string, error) {
		n++
		if args[1] == "delete" {
			return "", fmtErr("unknown connection")
		}
		return "", nil
	}, plan)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("n=%d", n)
	}
}

type fmtErr string

func (e fmtErr) Error() string { return string(e) }
