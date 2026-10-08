// Package protocol is the LAN Panel wire contract.
// Discovery is solicit (probe) + unicast reply (robot). Passwords never appear here.
package protocol

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	Kind         = "xgc2-lan-beacon"
	KindSolicit  = "xgc2-lan-solicit"
	Version      = 2
	UDPPort      = 19518
	ControlPort  = 19519
	ProbePort    = 3400
	SolicitEvery = 500 * time.Millisecond // 2 Hz while a page is watching
	StaleAfter   = 2 * time.Second
	DropAfter    = 4 * time.Second
	MaxUDPBytes  = 1400
)

// Solicit is sent by the probe on every local segment while someone is viewing.
type Solicit struct {
	V    int    `json:"v"`
	Kind string `json:"kind"`
}

// Beacon is the robot's unicast reply to a solicit. control_port is the TCP apply port.
type Beacon struct {
	V               int      `json:"v"`
	Kind            string   `json:"kind"`
	ID              string   `json:"id"`
	Hostname        string   `json:"hostname"`
	TSUnixMS        int64    `json:"ts_unix_ms"`
	ControlPort     int      `json:"control_port"`
	ControlInstance string   `json:"control_instance"`
	ControlName     string   `json:"control_name"`
	DefaultIface    string   `json:"default_iface,omitempty"`
	SSHUser         string   `json:"ssh_user,omitempty"`
	Users           []string `json:"users,omitempty"`
	Ifaces          []Iface  `json:"ifaces"`
}

// Iface is one NIC snapshot. DNS may be global (resolv.conf) repeated per row.
type Iface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Kind      string   `json:"kind"` // wifi | ethernet | other
	Up        bool     `json:"up"`
	Addrs     []string `json:"addrs,omitempty"`
	SSID      string   `json:"ssid,omitempty"`
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	Metric    int      `json:"metric,omitempty"`
	IsDefault bool     `json:"is_default"`
	SignalDbm *int     `json:"signal_dbm,omitempty"`
}

// ApplyRequest is POSTed over TCP to the robot control port.
type ApplyRequest struct {
	Iface       string   `json:"iface"`
	SSID        string   `json:"ssid,omitempty"`
	Password    string   `json:"password,omitempty"`
	Address     string   `json:"address,omitempty"`
	Gateway     string   `json:"gateway,omitempty"`
	DNS         []string `json:"dns,omitempty"`
	MakeDefault bool     `json:"make_default"`
}

// ApplyResult is returned after NetworkManager work.
type ApplyResult struct {
	OK             bool   `json:"ok"`
	Applied        bool   `json:"applied"`
	Persisted      bool   `json:"persisted"`
	FailureStage   string `json:"failure_stage,omitempty"`
	PartialEffects bool   `json:"partial_effects,omitempty"`
	Gone           bool   `json:"gone,omitempty"`
	Message        string `json:"message,omitempty"`
	Warning        string `json:"warning,omitempty"`
}

func MarshalSolicit() ([]byte, error) {
	return json.Marshal(Solicit{V: Version, Kind: KindSolicit})
}

func IsSolicit(raw []byte) bool {
	var s Solicit
	if err := json.Unmarshal(raw, &s); err != nil {
		return false
	}
	return s.Kind == KindSolicit && s.V == Version
}

func MarshalBeacon(b Beacon) ([]byte, error) {
	b.V = Version
	b.Kind = Kind
	if b.ControlPort == 0 {
		b.ControlPort = ControlPort
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxUDPBytes {
		return nil, fmt.Errorf("beacon payload %d bytes exceeds %d", len(raw), MaxUDPBytes)
	}
	return raw, nil
}

func ParseBeacon(raw []byte) (Beacon, error) {
	var b Beacon
	if err := json.Unmarshal(raw, &b); err != nil {
		return Beacon{}, err
	}
	if b.Kind != Kind {
		return Beacon{}, fmt.Errorf("not a lan-panel beacon")
	}
	if b.V != Version {
		return Beacon{}, fmt.Errorf("unsupported beacon version %d", b.V)
	}
	if len(raw) > MaxUDPBytes {
		return Beacon{}, fmt.Errorf("beacon exceeds byte budget")
	}
	if b.ID == "" || b.Hostname == "" || len(b.ID) > 128 || len(b.Hostname) > 253 || b.ControlInstance == "" || len(b.ControlInstance) > 128 || b.ControlName == "" || len(b.ControlName) > 253 || strings.ContainsAny(b.ControlName, " /\\\x00\r\n:@") {
		return Beacon{}, fmt.Errorf("beacon missing id or hostname")
	}
	if b.ControlPort == 0 {
		b.ControlPort = ControlPort
	}
	if b.ControlPort < 1 || b.ControlPort > 65535 {
		return Beacon{}, fmt.Errorf("invalid control port")
	}
	return b, nil
}

// LimitedBroadcast is 255.255.255.255 — all hosts on the sending L2, one hop.
func LimitedBroadcast() net.IP {
	return net.IPv4bcast
}
