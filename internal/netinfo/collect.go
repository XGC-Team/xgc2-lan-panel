package netinfo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
)

// Host is the OS surface Collect reads. Tests inject fakes.
type Host struct {
	ReadFile   func(string) ([]byte, error)
	ReadDir    func(string) ([]os.DirEntry, error)
	Stat       func(string) (os.FileInfo, error)
	Hostname   func() (string, error)
	Interfaces func() ([]net.Interface, error)
	Command    func(context.Context, string, ...string) ([]byte, error)
}

func DefaultHost() Host {
	return Host{
		ReadFile:   boundedReadFile,
		ReadDir:    os.ReadDir,
		Stat:       os.Stat,
		Hostname:   os.Hostname,
		Interfaces: net.Interfaces,
		Command:    RunCommand,
	}
}

func Collect(h Host) (protocol.Beacon, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return CollectContext(ctx, h)
}

func CollectContext(ctx context.Context, h Host) (protocol.Beacon, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Beacon{}, err
	}
	if h.ReadFile == nil {
		h = DefaultHost()
	}
	hostname, err := h.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	id := machineID(h)
	if id == "" {
		id = hostname
	}
	dns := ParseResolv(readFile(h, "/etc/resolv.conf"))
	routes := ParseRoutes(readFile(h, "/proc/net/route"))
	users := ParseLoginUsers(readFile(h, "/etc/passwd"))
	ifaces, err := h.Interfaces()
	if err != nil {
		return protocol.Beacon{}, err
	}
	if len(ifaces) > 64 {
		return protocol.Beacon{}, errors.New("interface count exceeds snapshot budget")
	}
	var out []protocol.Iface
	for _, ni := range ifaces {
		if err := ctx.Err(); err != nil {
			return protocol.Beacon{}, err
		}
		if skipIface(ni.Name) {
			continue
		}
		row := protocol.Iface{
			Name: ni.Name,
			MAC:  ni.HardwareAddr.String(),
			Kind: ifaceKind(h, ni.Name),
			Up:   ni.Flags&net.FlagUp != 0,
			DNS:  dns,
		}
		addrs, _ := ni.Addrs()
		for _, a := range addrs {
			s := a.String()
			ip, _, err := net.ParseCIDR(s)
			if err != nil || ip == nil || ip.To4() == nil {
				continue
			}
			row.Addrs = append(row.Addrs, s)
		}
		if r, ok := routes[ni.Name]; ok {
			row.Gateway = r.Gateway
			row.Metric = r.Metric
			row.IsDefault = r.Default
		}
		if row.Kind == "wifi" {
			row.SSID, row.SignalDbm = wifiOn(ctx, h, ni.Name)
		}
		if row.Kind == "other" {
			continue
		}
		out = append(out, row)
	}
	def := ""
	bestMetric := int(^uint(0) >> 1)
	for _, row := range out {
		if row.IsDefault && (def == "" || row.Metric < bestMetric) {
			def = row.Name
			bestMetric = row.Metric
		}
	}
	if err := ctx.Err(); err != nil {
		return protocol.Beacon{}, err
	}
	ssh := ""
	if len(users) > 0 {
		ssh = users[0]
	}
	return protocol.Beacon{
		ID:           id,
		Hostname:     hostname,
		DefaultIface: def,
		SSHUser:      ssh,
		Users:        users,
		Ifaces:       out,
	}, nil
}

type routeRow struct {
	Gateway string
	Metric  int
	Default bool
}

func ParseRoutes(raw []byte) map[string]routeRow {
	out := map[string]routeRow{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	if !sc.Scan() {
		return out
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		iface := fields[0]
		dest := fields[1]
		gwHex := fields[2]
		metric, _ := strconv.Atoi(fields[6])
		if dest != "00000000" {
			continue
		}
		gw := parseLEHexIPv4(gwHex)
		prev, ok := out[iface]
		if ok && prev.Default && prev.Metric <= metric {
			continue
		}
		out[iface] = routeRow{Gateway: gw, Metric: metric, Default: true}
	}
	return out
}

func parseLEHexIPv4(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return ""
	}
	n := binary.LittleEndian.Uint32(b)
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip.String()
}

func ParseResolv(raw []byte) []string {
	var dns []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && net.ParseIP(fields[1]) != nil {
			dns = append(dns, fields[1])
		}
	}
	return dns
}

func ParseLoginUsers(raw []byte) []string {
	var users []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		name := parts[0]
		uid, err := strconv.Atoi(parts[2])
		if err != nil || uid < 1000 {
			continue
		}
		shell := parts[6]
		if strings.Contains(shell, "nologin") || strings.HasSuffix(shell, "/false") {
			continue
		}
		switch name {
		case "nobody", "nfsnobody", "snapd-range-524288-root":
			continue
		}
		users = append(users, name)
	}
	return users
}

func ParseIWLink(raw []byte) (ssid string, dbm *int) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "SSID:") {
			ssid = strings.TrimSpace(strings.TrimPrefix(line, "SSID:"))
		}
		if strings.HasPrefix(line, "signal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				n, err := strconv.Atoi(strings.TrimSuffix(fields[1], "dBm"))
				if err == nil {
					dbm = &n
				}
			}
		}
	}
	return ssid, dbm
}

type LocalIPv4 struct {
	Iface string
	CIDR  string
	IP    net.IP
}

func ListLocalIPv4() []LocalIPv4 {
	return listLocalIPv4(DefaultHost())
}

func listLocalIPv4(h Host) []LocalIPv4 {
	ifaces, err := h.Interfaces()
	if err != nil {
		return nil
	}
	var out []LocalIPv4
	for _, ni := range ifaces {
		if SkipVirtual(ni.Name) || ni.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ni.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			s := addr.String()
			ip, _, err := net.ParseCIDR(s)
			if err != nil || ip == nil || ip.To4() == nil {
				continue
			}
			out = append(out, LocalIPv4{Iface: ni.Name, CIDR: s, IP: ip.To4()})
		}
	}
	return out
}

// SolicitTargets is limited broadcast, each iface's directed broadcast, loopback,
// and each local unicast. Broadcasts do not loop back to this host, so a beacon
// on the same machine is only reachable by unicast (127.0.0.1 or the NIC IP).
func SolicitTargets(locals []LocalIPv4) []net.IP {
	seen := map[string]bool{}
	var out []net.IP
	add := func(ip net.IP) {
		v4 := ip.To4()
		if v4 == nil {
			return
		}
		key := v4.String()
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, append(net.IP(nil), v4...))
	}
	add(net.IPv4bcast)
	add(net.IPv4(127, 0, 0, 1))
	for _, local := range locals {
		ip := local.IP
		if ip == nil {
			parsed, _, err := net.ParseCIDR(local.CIDR)
			if err == nil {
				ip = parsed
			}
		}
		add(ip)
		bcast, err := BroadcastAddr(local.CIDR)
		if err != nil {
			continue
		}
		add(bcast)
	}
	return out
}

func BroadcastAddr(cidr string) (net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("not ipv4")
	}
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = ip.To4()[i] | ^ipnet.Mask[i]
	}
	return bcast, nil
}

func SkipVirtual(name string) bool {
	return skipIface(name) || strings.HasPrefix(name, "xgc2-")
}

func skipIface(name string) bool {
	if name == "lo" {
		return true
	}
	prefixes := []string{"docker", "br-", "veth", "virbr", "dummy", "tun", "tap", "wg", "cni", "flannel", "kube"}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func ifaceKind(h Host, name string) string {
	wireless := filepath.Join("/sys/class/net", name, "wireless")
	if _, err := h.Stat(wireless); err == nil {
		return "wifi"
	}
	raw := strings.TrimSpace(string(readFile(h, filepath.Join("/sys/class/net", name, "type"))))
	if raw == "1" {
		return "ethernet"
	}
	return "other"
}

func wifiOn(ctx context.Context, h Host, name string) (string, *int) {
	if h.Command == nil {
		return "", nil
	}
	if out, err := h.Command(ctx, "iw", "dev", name, "link"); err == nil {
		ssid, dbm := ParseIWLink(out)
		if ssid != "" {
			return ssid, dbm
		}
	}
	if out, err := h.Command(ctx, "iwgetid", "-r", name); err == nil {
		ssid := strings.TrimSpace(string(out))
		if ssid != "" {
			return ssid, nil
		}
	}
	if out, err := h.Command(ctx, "nmcli", "-t", "-f", "GENERAL.CONNECTION", "device", "show", name); err == nil {
		conn := strings.TrimSpace(string(out))
		conn = strings.TrimPrefix(conn, "GENERAL.CONNECTION:")
		conn = strings.TrimSpace(conn)
		if conn != "" && conn != "--" {
			if ssidOut, err := h.Command(ctx, "nmcli", "-t", "-f", "802-11-wireless.ssid", "connection", "show", conn); err == nil {
				ssid := strings.TrimSpace(string(ssidOut))
				ssid = strings.TrimPrefix(ssid, "802-11-wireless.ssid:")
				ssid = strings.TrimSpace(ssid)
				if ssid != "" {
					return ssid, nil
				}
			}
		}
	}
	return "", nil
}

func machineID(h Host) string {
	id := strings.TrimSpace(string(readFile(h, "/etc/machine-id")))
	id = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, id)
	if len(id) > 32 {
		id = id[:32]
	}
	return id
}

func readFile(h Host, path string) []byte {
	if h.ReadFile == nil {
		return nil
	}
	b, err := h.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// Native command work is finite and fully joined; overflow never becomes a
// successful partial parser input.
const MaxNativeOutput = 64 << 10

type boundedOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Write(raw []byte) (int, error) {
	n := len(raw)
	remaining := MaxNativeOutput - b.buffer.Len()
	if len(raw) > remaining {
		b.overflow = true
		raw = raw[:remaining]
	}
	_, _ = b.buffer.Write(raw)
	return n, nil
}
func RunCommand(parent context.Context, name string, args ...string) ([]byte, error) {
	return RunCommandBounded(parent, 2*time.Second, name, args...)
}
func RunCommandBounded(parent context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	var output boundedOutput
	command.Stdout = &output
	command.Stderr = &output
	command.WaitDelay = time.Second
	err := command.Run()
	if err == nil && output.overflow {
		err = errors.New("native output exceeds byte budget")
	}
	return output.buffer.Bytes(), err
}
func boundedReadFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxNativeOutput+1))
	if len(raw) > MaxNativeOutput {
		return nil, errors.New("host snapshot input exceeds byte budget")
	}
	return raw, err
}
