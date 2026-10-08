package probe

import (
	"net"
	"sort"
	"sync"
	"time"

	"github.com/XGC-Team/xgc2-lan-panel/internal/netinfo"
	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
)

type Robot struct {
	Beacon   protocol.Beacon `json:"beacon"`
	ReachIP  string          `json:"reach_ip"`
	LastSeen time.Time       `json:"last_seen"`
	Stale    bool            `json:"stale"`
}

type Registry struct {
	mu    sync.Mutex
	byID  map[string]Robot
	now   func() time.Time
	local []*net.IPNet
}

func NewRegistry(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{byID: map[string]Robot{}, now: now, local: localNets()}
}

func (r *Registry) Observe(src string, b protocol.Beacon) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked()
	if _, exists := r.byID[b.ID]; !exists && len(r.byID) >= 64 {
		return
	}
	prev := r.byID[b.ID].ReachIP
	r.byID[b.ID] = Robot{
		Beacon:   b,
		ReachIP:  pickReach(src, b, prev, r.local),
		LastSeen: r.now(),
	}
}

func (r *Registry) Get(id string) (Robot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked()
	row, ok := r.byID[id]
	if !ok {
		return Robot{}, false
	}
	row.Stale = r.now().Sub(row.LastSeen) >= protocol.StaleAfter
	return row, true
}

func (r *Registry) Evict(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, id)
}

// TakeFresh returns a live reply. Stale or missing rows are removed.
func (r *Registry) TakeFresh(id string) (Robot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked()
	row, ok := r.byID[id]
	if !ok {
		return Robot{}, false
	}
	if r.now().Sub(row.LastSeen) >= protocol.StaleAfter {
		delete(r.byID, id)
		return Robot{}, false
	}
	return row, true
}

func (r *Registry) List() []Robot {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked()
	out := make([]Robot, 0, len(r.byID))
	now := r.now()
	for _, row := range r.byID {
		row.Stale = now.Sub(row.LastSeen) >= protocol.StaleAfter
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Beacon.Hostname != out[j].Beacon.Hostname {
			return out[i].Beacon.Hostname < out[j].Beacon.Hostname
		}
		return out[i].Beacon.ID < out[j].Beacon.ID
	})
	return out
}

func (r *Registry) expireLocked() {
	now := r.now()
	for id, row := range r.byID {
		if now.Sub(row.LastSeen) >= protocol.DropAfter {
			delete(r.byID, id)
		}
	}
}

func pickReach(src string, b protocol.Beacon, prev string, local []*net.IPNet) string {
	addrs := advertisedIPv4(b)
	def := defaultIPv4(b)
	if len(local) == 0 {
		if def != "" {
			return def
		}
		if prev != "" {
			return prev
		}
		return src
	}
	// Default NIC on a shared segment is stable across per-NIC solicits.
	if def != "" && onLocal(def, local) {
		return def
	}
	if prev != "" && containsString(addrs, prev) && onLocal(prev, local) {
		return prev
	}
	if onLocal(src, local) {
		return src
	}
	for _, addr := range addrs {
		if onLocal(addr, local) {
			return addr
		}
	}
	if prev != "" {
		return prev
	}
	return src
}

func advertisedIPv4(b protocol.Beacon) []string {
	var out []string
	for _, iface := range b.Ifaces {
		for _, addr := range iface.Addrs {
			ip, _, err := net.ParseCIDR(addr)
			if err == nil && ip.To4() != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

func defaultIPv4(b protocol.Beacon) string {
	for _, iface := range b.Ifaces {
		if iface.Name != b.DefaultIface && !iface.IsDefault {
			continue
		}
		for _, addr := range iface.Addrs {
			ip, _, err := net.ParseCIDR(addr)
			if err == nil && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func onLocal(ip string, local []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range local {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func localNets() []*net.IPNet {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var nets []*net.IPNet
	for _, ni := range ifaces {
		if netinfo.SkipVirtual(ni.Name) {
			continue
		}
		addrs, err := ni.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipn, ok := addr.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if bits != 32 || ones == 0 {
				continue
			}
			copyNet := *ipn
			copyIP := make(net.IP, len(ipn.IP))
			copy(copyIP, ipn.IP)
			copyNet.IP = copyIP
			nets = append(nets, &copyNet)
		}
	}
	return nets
}
