package probe

import (
	"net"
	"testing"
	"time"

	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
)

func TestPickReachPrefersLocalSubnet(t *testing.T) {
	_, lan, err := net.ParseCIDR("192.168.100.251/24")
	if err != nil {
		t.Fatal(err)
	}
	b := protocol.Beacon{Ifaces: []protocol.Iface{
		{Name: "wlan1", Addrs: []string{"192.168.100.40/24"}},
		{Name: "docker0", Addrs: []string{"172.17.0.1/16"}},
	}}
	got := pickReach("172.17.0.1", b, "", []*net.IPNet{lan})
	if got != "192.168.100.40" {
		t.Fatalf("got %s", got)
	}
}

func TestPickReachPrefersDefaultThenSticks(t *testing.T) {
	_, lanA, err := net.ParseCIDR("192.168.100.251/24")
	if err != nil {
		t.Fatal(err)
	}
	_, lanB, err := net.ParseCIDR("10.8.0.251/24")
	if err != nil {
		t.Fatal(err)
	}
	local := []*net.IPNet{lanA, lanB}
	b := protocol.Beacon{
		ID:           "a",
		Hostname:     "xavier",
		DefaultIface: "wlan1",
		Ifaces: []protocol.Iface{
			{Name: "wlan1", Addrs: []string{"192.168.100.40/24"}, IsDefault: true},
			{Name: "eth0", Addrs: []string{"10.8.0.40/24"}},
		},
	}
	first := pickReach("10.8.0.40", b, "", local)
	if first != "192.168.100.40" {
		t.Fatalf("default on shared segment: %s", first)
	}
	if second := pickReach("10.8.0.40", b, first, local); second != first {
		t.Fatalf("flipped to %s", second)
	}
	if third := pickReach("192.168.100.40", b, first, local); third != first {
		t.Fatalf("flipped to %s", third)
	}
}

func TestReachIPDoesNotFollowSolicitSource(t *testing.T) {
	_, lanA, _ := net.ParseCIDR("192.168.100.251/24")
	_, lanB, _ := net.ParseCIDR("10.8.0.251/24")
	reg := NewRegistry(nil)
	reg.local = []*net.IPNet{lanA, lanB}
	b := protocol.Beacon{
		ID:           "a",
		Hostname:     "xavier",
		DefaultIface: "wlan1",
		Ifaces: []protocol.Iface{
			{Name: "wlan1", Addrs: []string{"192.168.100.40/24"}, IsDefault: true},
			{Name: "eth0", Addrs: []string{"10.8.0.40/24"}},
		},
	}
	reg.Observe("10.8.0.40", b)
	reg.Observe("192.168.100.40", b)
	reg.Observe("10.8.0.40", b)
	row, ok := reg.Get("a")
	if !ok || row.ReachIP != "192.168.100.40" {
		t.Fatalf("reach=%s ok=%v", row.ReachIP, ok)
	}
}

func TestRegistryStaleAndDrop(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	reg := NewRegistry(func() time.Time { return now })
	reg.Observe("192.168.100.40", protocol.Beacon{ID: "a", Hostname: "xavier"})
	now = now.Add(2100 * time.Millisecond)
	list := reg.List()
	if len(list) != 1 || !list[0].Stale {
		t.Fatalf("stale: %+v", list)
	}
	now = now.Add(2100 * time.Millisecond)
	if len(reg.List()) != 0 {
		t.Fatal("expected drop after DropAfter")
	}
}

func TestTakeFreshEvictsStale(t *testing.T) {
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	reg := NewRegistry(func() time.Time { return now })
	reg.Observe("192.168.100.40", protocol.Beacon{ID: "a", Hostname: "xavier"})
	if _, ok := reg.TakeFresh("a"); !ok {
		t.Fatal("fresh")
	}
	now = now.Add(3 * time.Second)
	if _, ok := reg.TakeFresh("a"); ok {
		t.Fatal("stale must evict")
	}
	if _, ok := reg.Get("a"); ok {
		t.Fatal("gone from panel")
	}
}
