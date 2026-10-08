package beacon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/XGC-Team/xgc2-lan-panel/internal/netinfo"
	"github.com/XGC-Team/xgc2-lan-panel/internal/nmapply"
	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
	"github.com/XGC-Team/xgc2-lan-panel/internal/runtimepolicy"
	xrpc "github.com/XGC-Team/xgc2-xrpc/go"
	"github.com/XGC-Team/xgc2-xrpc/go/httpx"
	"golang.org/x/sys/unix"
)

type Options struct {
	UDPAddr     string
	ControlAddr string
	Host        netinfo.Host
	Nmcli       func(context.Context, []string) (string, error)
	TLSConfig   *tls.Config
	ControlName string
	InstanceID  string
	ControlPort int
	Now         func() time.Time
	Policy      *xrpc.Policy
	snapshots   *snapshotCache
}

type snapshotCache struct {
	mu      sync.RWMutex
	beacon  protocol.Beacon
	updated time.Time
	err     error
}

func DefaultOptions() Options {
	return Options{
		UDPAddr:     ":" + strconv.Itoa(protocol.UDPPort),
		ControlAddr: ":" + strconv.Itoa(protocol.ControlPort),
		Host:        netinfo.DefaultHost(),
		Nmcli: func(ctx context.Context, args []string) (string, error) {
			out, err := netinfo.RunCommandBounded(ctx, 25*time.Second, "nmcli", append([]string{"--wait", "20"}, args...)...)
			if err != nil {
				return string(out), err
			}
			return string(out), nil
		},
		Now: time.Now,
	}
}

func Run(ctx context.Context, opt Options) (returnErr error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Host.ReadFile == nil {
		opt.Host = netinfo.DefaultHost()
	}
	if opt.Nmcli == nil {
		opt.Nmcli = DefaultOptions().Nmcli
	}
	if opt.ControlAddr == "" {
		opt.ControlAddr = ":" + strconv.Itoa(protocol.ControlPort)
	}
	if opt.UDPAddr == "" {
		opt.UDPAddr = ":" + strconv.Itoa(protocol.UDPPort)
	}

	if opt.TLSConfig == nil || opt.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || opt.TLSConfig.VerifyConnection == nil || opt.ControlName == "" {
		return errors.New("authenticated LAN control TLS identity and caller grant required")
	}
	policy, err := runtimepolicy.Resolve(os.Environ(), "beacon")
	if err != nil {
		return err
	}
	opt.Policy = policy
	var boot [16]byte
	if _, err := rand.Read(boot[:]); err != nil {
		return err
	}
	opt.InstanceID = hex.EncodeToString(boot[:])
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opt.ControlAddr)
	if err != nil {
		return err
	}
	opt.ControlPort = listener.Addr().(*net.TCPAddr).Port
	opt.snapshots = &snapshotCache{}
	initial, initialErr := snapshotFresh(ctx, opt)
	opt.snapshots.beacon, opt.snapshots.updated, opt.snapshots.err = initial, time.Now(), initialErr
	options, err := (httpx.HostOptions{InstanceID: opt.InstanceID, DiscoveryPaths: []string{"/v1/describe"}}).WithPolicy(policy)
	if err != nil {
		listener.Close()
		return err
	}
	host, err := httpx.ServeTLS(listener, Handler(opt), opt.TLSConfig, options)
	if err != nil {
		listener.Close()
		return err
	}
	serveCtx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		returnErr = errors.Join(returnErr, host.Shutdown(shutdown))
	}()

	pc, err := listenUDP(opt.UDPAddr)
	if err != nil {
		stopServing()
		return err
	}
	defer pc.Close()
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); replySolicits(serveCtx, pc, opt) }()
	go func() { defer readers.Done(); maintainSnapshots(serveCtx, opt) }()
	defer func() { stopServing(); pc.Close(); readers.Wait() }()

	log.Printf("wait for solicit on udp %s; control %s", opt.UDPAddr, opt.ControlAddr)
	select {
	case <-ctx.Done():
		return nil
	case <-host.Done():
		return host.Wait()
	}
}

func SnapshotOnce(opt Options) (protocol.Beacon, error) {
	if opt.Host.ReadFile == nil {
		opt.Host = netinfo.DefaultHost()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return snapshot(opt)
}

func snapshot(opt Options) (protocol.Beacon, error) {
	if opt.snapshots != nil {
		opt.snapshots.mu.RLock()
		defer opt.snapshots.mu.RUnlock()
		if time.Since(opt.snapshots.updated) > 10*time.Second {
			return protocol.Beacon{}, errors.New("maintained LAN snapshot expired")
		}
		return opt.snapshots.beacon, opt.snapshots.err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return snapshotFresh(ctx, opt)
}
func snapshotFresh(parent context.Context, opt Options) (protocol.Beacon, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	b, err := netinfo.CollectContext(ctx, opt.Host)
	if err != nil {
		return protocol.Beacon{}, err
	}
	b.TSUnixMS = opt.Now().UnixMilli()
	b.ControlPort = opt.ControlPort
	if b.ControlPort == 0 {
		b.ControlPort = protocol.ControlPort
	}
	b.ControlInstance = opt.InstanceID
	b.ControlName = opt.ControlName
	b.V = protocol.Version
	b.Kind = protocol.Kind
	return b, nil
}

func maintainSnapshots(ctx context.Context, opt Options) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			beacon, err := snapshotFresh(ctx, opt)
			opt.snapshots.mu.Lock()
			opt.snapshots.beacon, opt.snapshots.err, opt.snapshots.updated = beacon, err, time.Now()
			opt.snapshots.mu.Unlock()
		}
	}
}

func replySolicits(ctx context.Context, pc net.PacketConn, opt Options) {
	buf := make([]byte, 2048)
	for {
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if !protocol.IsSolicit(buf[:n]) {
			continue
		}
		b, err := snapshot(opt)
		if err != nil {
			log.Printf("collect: %v", err)
			continue
		}
		raw, err := protocol.MarshalBeacon(b)
		if err != nil {
			log.Printf("marshal: %v", err)
			continue
		}
		if _, err := pc.WriteTo(raw, addr); err != nil {
			log.Printf("reply %s: %v", addr, err)
		}
	}
}

func apply(ctx context.Context, opt Options, req protocol.ApplyRequest) (protocol.ApplyResult, int) {
	if err := nmapply.Validate(req); err != nil {
		return protocol.ApplyResult{Message: err.Error(), FailureStage: "validate"}, http.StatusBadRequest
	}
	kind := ""
	if b, err := snapshot(opt); err == nil {
		for _, iface := range b.Ifaces {
			if iface.Name == req.Iface {
				kind = iface.Kind
				break
			}
		}
	}
	activeOut, activeErr := opt.Nmcli(ctx, []string{"-t", "-f", "NAME,DEVICE,TYPE", "connection", "show", "--active"})
	if activeErr != nil {
		return protocol.ApplyResult{Message: "NetworkManager snapshot unavailable", FailureStage: "snapshot"}, 503
	}
	active := nmapply.ParseActiveConnections(activeOut)
	plan, err := nmapply.BuildPlan(req, kind, active)
	if err != nil {
		return protocol.ApplyResult{Message: err.Error(), FailureStage: "validate"}, http.StatusBadRequest
	}
	if err := nmapply.Run(func(args []string) (string, error) { return opt.Nmcli(ctx, args) }, plan); err != nil {
		return protocol.ApplyResult{Message: "NetworkManager command outcome unknown; control is held until owner recovery", Warning: plan.Warning, FailureStage: "outcome-unknown", PartialEffects: true}, http.StatusInternalServerError
	}
	if err := verifyApplied(ctx, opt, req, plan); err != nil {
		return protocol.ApplyResult{Message: err.Error(), Warning: plan.Warning, FailureStage: "postcondition", PartialEffects: true}, http.StatusConflict
	}
	return protocol.ApplyResult{OK: true, Applied: true, Persisted: true, Message: "applied", Warning: plan.Warning}, http.StatusOK
}

func listenUDP(addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			})
		},
	}
	return lc.ListenPacket(context.Background(), "udp4", addr)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func Handler(opt Options) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/runtime-policy", func(w http.ResponseWriter, r *http.Request) {
		if opt.Policy == nil {
			http.Error(w, "policy unavailable", 503)
			return
		}
		writeJSON(w, opt.Policy.Effective())
	})
	mutations := make(chan struct{}, 1)
	type receipt struct {
		digest [32]byte
		done   bool
		result protocol.ApplyResult
		status int
	}
	var receiptMu sync.Mutex
	receipts := make(map[string]receipt)
	blocked := false
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		receiptMu.Lock()
		hold := blocked
		receiptMu.Unlock()
		writeJSON(w, map[string]any{"ok": !hold, "recovery_required": hold})
	})
	mux.HandleFunc("GET /v1/describe", func(w http.ResponseWriter, r *http.Request) {
		b, err := snapshot(opt)
		if err != nil {
			http.Error(w, "snapshot unavailable", 500)
			return
		}
		writeJSON(w, xrpc.ServiceRef{TargetID: b.ID, Service: "xgc2.lan.v1.Beacon", APIVersion: "2", InstanceID: opt.InstanceID, Profile: xrpc.HTTP, Endpoint: xrpc.Endpoint{Kind: "https", Address: "https://" + net.JoinHostPort(opt.ControlName, strconv.Itoa(b.ControlPort))}})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Err() != nil {
			http.Error(w, "request cancelled", 503)
			return
		}
		b, err := snapshot(opt)
		if err != nil {
			http.Error(w, "snapshot unavailable", 500)
			return
		}
		writeJSON(w, b)
	})
	mux.HandleFunc("POST /v1/apply", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
		if err != nil {
			http.Error(w, "command exceeds byte budget", 413)
			return
		}
		var req protocol.ApplyRequest
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || dec.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid command", 400)
			return
		}
		normalized, err := json.Marshal(req)
		if err != nil {
			http.Error(w, "invalid command", 400)
			return
		}
		hash := sha256.Sum256(normalized)
		id := r.Header.Get(httpx.RequestIDHeader)
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || id == "" {
			http.Error(w, "authenticated call identity required", 403)
			return
		}
		principal := sha256.Sum256(r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
		key := hex.EncodeToString(principal[:]) + ":" + id
		receiptMu.Lock()
		previous, exists := receipts[key]
		if exists {
			receiptMu.Unlock()
			if previous.digest != hash {
				http.Error(w, "request identity conflict", 409)
				return
			}
			if !previous.done {
				http.Error(w, "operation still running; outcome unknown", 409)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(previous.status)
			_ = json.NewEncoder(w).Encode(previous.result)
			return
		}
		if len(receipts) >= 128 {
			receiptMu.Unlock()
			http.Error(w, "boot receipt capacity reached", 429)
			return
		}
		if r.Context().Err() != nil {
			receiptMu.Unlock()
			http.Error(w, "request cancelled before admission", 503)
			return
		}
		select {
		case mutations <- struct{}{}:
		default:
			receiptMu.Unlock()
			http.Error(w, "network writer busy", 429)
			return
		}
		receipts[key] = receipt{digest: hash}
		receiptMu.Unlock()
		// NetworkManager owns activation after admission. A caller leaving must
		// not release its writer while the native provider is still working.
		domainCtx, cancelDomain := context.WithTimeout(context.Background(), 30*time.Second)
		result, status := apply(domainCtx, opt, req)
		cancelDomain()
		receiptMu.Lock()
		receipts[key] = receipt{digest: hash, done: true, result: result, status: status}
		if result.FailureStage == "outcome-unknown" {
			blocked = true
		} else {
			<-mutations
		}
		receiptMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(result)
	})
	return mux
}

// Check the actual NetworkManager state once after its native activation
// completes. This is a provider postcondition, not a Core polling probe.
func verifyApplied(ctx context.Context, opt Options, req protocol.ApplyRequest, plan nmapply.Plan) error {
	out, err := opt.Nmcli(ctx, []string{"-t", "-f", "GENERAL.STATE,GENERAL.CONNECTION,IP4.ADDRESS,IP4.GATEWAY,IP4.DNS", "device", "show", req.Iface})
	if err != nil {
		return errors.New("NetworkManager postcondition unavailable")
	}
	fields := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if at := strings.IndexByte(key, '['); at >= 0 {
			key = key[:at]
		}
		fields[key] = append(fields[key], strings.ReplaceAll(value, "\\:", ":"))
	}
	has := func(key, value string) bool {
		for _, actual := range fields[key] {
			if actual == value {
				return true
			}
		}
		return false
	}
	connected := false
	for _, state := range fields["GENERAL.STATE"] {
		if state == "100" || strings.HasPrefix(state, "100 ") {
			connected = true
		}
	}
	profile := plan.Commands[len(plan.Commands)-1].Args[2]
	if !connected || !has("GENERAL.CONNECTION", profile) {
		return errors.New("NetworkManager connection is not active")
	}
	if req.Address != "" && !has("IP4.ADDRESS", req.Address) {
		return errors.New("requested address is not applied")
	}
	if req.Gateway != "" && !has("IP4.GATEWAY", req.Gateway) {
		return errors.New("requested gateway is not applied")
	}
	for _, dns := range req.DNS {
		if !has("IP4.DNS", dns) {
			return errors.New("requested DNS is not applied")
		}
	}
	if req.SSID != "" {
		ssid, err := opt.Nmcli(ctx, []string{"-g", "802-11-wireless.ssid", "connection", "show", profile})
		if err != nil || strings.TrimSpace(ssid) != req.SSID {
			return errors.New("requested SSID is not applied")
		}
	}
	if req.MakeDefault {
		metric, err := opt.Nmcli(ctx, []string{"-g", "ipv4.route-metric", "connection", "show", profile})
		if err != nil || strings.TrimSpace(metric) != "50" {
			return errors.New("requested route metric is not persisted")
		}
		raw, err := opt.Host.ReadFile("/proc/net/route")
		if err != nil || len(raw) > netinfo.MaxNativeOutput {
			return errors.New("native default route is unavailable")
		}
		routes := netinfo.ParseRoutes(raw)
		target, ok := routes[req.Iface]
		if !ok || !target.Default || target.Metric != 50 {
			return errors.New("requested default route is not applied")
		}
		for iface, route := range routes {
			if iface != req.Iface && route.Default && route.Metric <= target.Metric {
				return errors.New("another native route remains preferred")
			}
		}
	}
	return nil
}
