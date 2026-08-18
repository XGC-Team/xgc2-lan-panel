package netinfo

import (
	"testing"
)

func TestParseRoutesDefault(t *testing.T) {
	raw := []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"wlan1\t00000000\t0100A8C0\t0003\t0\t0\t50\t00000000\t0\t0\t0\n" +
		"wlan0\t00000000\t0109A8C0\t0003\t0\t0\t20601\t00000000\t0\t0\t0\n" +
		"wlan1\t0000A8C0\t00000000\t0001\t0\t0\t50\t00FFFFFF\t0\t0\t0\n")
	routes := ParseRoutes(raw)
	if routes["wlan1"].Gateway != "192.168.0.1" || routes["wlan1"].Metric != 50 || !routes["wlan1"].Default {
		t.Fatalf("wlan1: %+v", routes["wlan1"])
	}
	if routes["wlan0"].Gateway != "192.168.9.1" || routes["wlan0"].Metric != 20601 {
		t.Fatalf("wlan0: %+v", routes["wlan0"])
	}
}

func TestParseResolvAndUsers(t *testing.T) {
	dns := ParseResolv([]byte("nameserver 192.168.100.1\nnameserver 8.8.8.8\n# comment\nsearch lan\n"))
	if len(dns) != 2 || dns[0] != "192.168.100.1" {
		t.Fatalf("dns=%v", dns)
	}
	users := ParseLoginUsers([]byte("root:x:0:0:root:/root:/bin/bash\n" +
		"agilex:x:1000:1000::/home/agilex:/bin/bash\n" +
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"))
	if len(users) != 1 || users[0] != "agilex" {
		t.Fatalf("users=%v", users)
	}
}

func TestParseIWLink(t *testing.T) {
	ssid, dbm := ParseIWLink([]byte("Connected to aa:bb\n\tSSID: BIU_5G\n\tsignal: -45 dBm\n"))
	if ssid != "BIU_5G" || dbm == nil || *dbm != -45 {
		t.Fatalf("ssid=%q dbm=%v", ssid, dbm)
	}
}

func TestBroadcastAddr(t *testing.T) {
	b, err := BroadcastAddr("192.168.100.40/24")
	if err != nil {
		t.Fatal(err)
	}
	if b.String() != "192.168.100.255" {
		t.Fatalf("got %s", b)
	}
}

func TestSolicitTargetsCoverEachSegment(t *testing.T) {
	got := SolicitTargets([]LocalIPv4{
		{Iface: "wlo1", CIDR: "192.168.100.251/24"},
		{Iface: "enp1", CIDR: "10.136.136.130/16"},
	})
	want := map[string]bool{
		"255.255.255.255": true,
		"127.0.0.1":       true,
		"192.168.100.251": true,
		"192.168.100.255": true,
		"10.136.136.130":  true,
		"10.136.255.255":  true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, ip := range got {
		if !want[ip.String()] {
			t.Fatalf("unexpected %s", ip)
		}
	}
}
