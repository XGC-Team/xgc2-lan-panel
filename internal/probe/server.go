package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/XGC-Team/xgc2-lan-panel/internal/controltls"
	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
	"github.com/XGC-Team/xgc2-lan-panel/internal/runtimepolicy"
	xrpc "github.com/XGC-Team/xgc2-xrpc/go"
	"github.com/XGC-Team/xgc2-xrpc/go/httpx"
	"golang.org/x/sys/unix"
)

type Options struct {
	Listen       string
	UDPAddr      string
	UI           fs.FS
	TLSConfig    *tls.Config
	TargetGrants controltls.TargetGrants
	Now          func() time.Time
}

func Run(ctx context.Context, opt Options) error {
	if opt.Listen == "" {
		opt.Listen = "127.0.0.1:" + strconv.Itoa(protocol.ProbePort)
	}
	if opt.UDPAddr == "" {
		// Ephemeral source. Robots own :19518; sharing that port with REUSEPORT
		// ate replies on the same host, and broadcasts never loop back.
		opt.UDPAddr = ":0"
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if !loopbackAuthority(opt.Listen) {
		return errors.New("LAN probe must listen on a numeric loopback address or localhost")
	}
	if len(opt.TargetGrants) < 1 || len(opt.TargetGrants) > 64 {
		return errors.New("bounded deployment LAN target grants required")
	}
	if opt.TLSConfig == nil || opt.TLSConfig.InsecureSkipVerify || len(opt.TLSConfig.Certificates) != 1 || opt.TLSConfig.RootCAs == nil {
		return errors.New("authenticated LAN client identity and trust bundle required")
	}
	policy, err := runtimepolicy.Resolve(os.Environ(), "probe")
	if err != nil {
		return err
	}
	hostOptions, err := (httpx.HostOptions{}).WithPolicy(policy)
	if err != nil {
		return err
	}
	reg := NewRegistry(opt.Now)
	hub := NewHub()
	clientConfig, err := (httpx.Config{LocalTargetID: "lan-probe", MaxInFlight: 8,
		TLSForService: func(ref xrpc.ServiceRef) (*tls.Config, error) {
			return opt.TargetGrants.TLSForService(opt.TLSConfig, ref)
		},
		DialContext: func(ctx context.Context, ref xrpc.ServiceRef) (net.Conn, error) {
			row, ok := reg.TakeFresh(ref.TargetID)
			if !ok || row.Beacon.ControlInstance != ref.InstanceID {
				return nil, errors.New("LAN service reference expired")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(row.ReachIP, strconv.Itoa(row.Beacon.ControlPort)))
		}}).WithPolicy(policy)
	if err != nil {
		return err
	}
	profile := httpx.NewProfile(clientConfig)
	defer profile.Close()
	publish := func() {
		raw, err := json.Marshal(reg.List())
		if err != nil {
			return
		}
		hub.Publish(raw)
	}

	pc, err := listenUDP(opt.UDPAddr)
	if err != nil {
		return err
	}
	defer pc.Close()

	workCtx, cancelWork := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Add(3)
	go func() { defer workers.Done(); readBeacons(workCtx, pc, reg, hub, publish) }()
	go func() { defer workers.Done(); staleTicker(workCtx, hub, publish) }()
	go func() { defer workers.Done(); solicitLoop(workCtx, pc, hub) }()
	defer func() { cancelWork(); pc.Close(); workers.Wait() }()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/runtime-policy", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, policy.Effective()) })
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"ok":         true,
			"robots":     len(reg.List()),
			"viewers":    hub.Viewers(),
			"soliciting": hub.Viewing(),
		})
	})
	mux.HandleFunc("GET /api/robots", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, reg.List())
	})
	mux.HandleFunc("GET /api/watch", func(w http.ResponseWriter, r *http.Request) {
		serveWatch(w, r, hub, publish)
	})
	mux.HandleFunc("POST /api/robots/{id}/apply", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		row, ok := reg.TakeFresh(id)
		if !ok {
			publish()
			writeJSONStatus(w, http.StatusConflict, protocol.ApplyResult{
				Gone:    true,
				Message: "回拨已过时，已从面板清掉这台车",
			})
			return
		}
		grant, allowed := opt.TargetGrants[id]
		if !allowed || grant.ServerName != row.Beacon.ControlName {
			http.Error(w, "robot discovery has no matching control authorization", 403)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, (1<<16)+1))
		if err != nil || len(body) > 1<<16 {
			http.Error(w, "command exceeds byte budget", 413)
			return
		}
		if !json.Valid(body) {
			http.Error(w, "invalid command JSON", 400)
			return
		}
		var identity [16]byte
		if _, err = rand.Read(identity[:]); err != nil {
			http.Error(w, "request identity unavailable", 500)
			return
		}
		ref := xrpc.ServiceRef{TargetID: row.Beacon.ID, Service: "xgc2.lan.v1.Beacon", APIVersion: "2", InstanceID: row.Beacon.ControlInstance, Profile: xrpc.HTTP, Endpoint: xrpc.Endpoint{Kind: "https", Address: "https://" + net.JoinHostPort(row.Beacon.ControlName, strconv.Itoa(row.Beacon.ControlPort))}}
		callCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		result, err := profile.Call(callCtx, xrpc.Call{Service: ref, Method: http.MethodPost, Path: "/v1/apply", RequestID: hex.EncodeToString(identity[:]), Payload: body})
		if err != nil {
			code := xrpc.Code(err)
			status := http.StatusBadGateway
			switch code {
			case "invalid_argument":
				status = 400
			case "resource_exhausted":
				status = 429
			case "conflict":
				status = 409
			case "deadline_exceeded":
				status = 504
			}
			disposition := xrpc.NotSent
			var failure *xrpc.CallError
			if errors.As(err, &failure) {
				disposition = failure.Disposition
			}
			writeJSONStatus(w, status, map[string]any{"ok": false, "message": fmt.Sprintf("LAN control failed: %s", code), "warning": "the robot may be switching networks; rediscover before any new command", "disposition": disposition})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(result.Status)
		_, _ = w.Write(result.Payload)
	})
	if opt.UI != nil {
		fileServer := http.FileServer(http.FS(opt.UI))
		mux.Handle("/", fileServer)
	} else {
		mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "xgc2-lan-panel probe API is up. Build web/ and embed it to serve the UI.\n")
		})
	}

	log.Printf("probe ui/api on http://%s  (solicit %s → :%d)", opt.Listen, pc.LocalAddr(), protocol.UDPPort)
	return httpx.RunEdge(ctx, opt.Listen, withCORS(mux), hostOptions)
}

func readBeacons(ctx context.Context, pc net.PacketConn, reg *Registry, hub *Hub, publish func()) {
	buf := make([]byte, 4096)
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
		if !hub.Viewing() {
			continue
		}
		b, err := protocol.ParseBeacon(buf[:n])
		if err != nil {
			continue
		}
		host, _, _ := net.SplitHostPort(addr.String())
		if host == "" {
			host = addr.String()
		}
		reg.Observe(host, b)
		publish()
	}
}

func staleTicker(ctx context.Context, hub *Hub, publish func()) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if hub.Viewing() {
				publish()
			}
		}
	}
}

func serveWatch(w http.ResponseWriter, r *http.Request, hub *Hub, publish func()) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	id, updates, viewers := hub.Subscribe()
	defer func() {
		left := hub.Unsubscribe(id)
		log.Printf("viewer left; viewers=%d", left)
	}()
	log.Printf("viewer watching; viewers=%d", viewers)
	publish()
	writeSSE(w, flusher, "viewers", mustJSON(map[string]int{"viewers": viewers}))
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case payload, open := <-updates:
			if !open {
				return
			}
			writeSSE(w, flusher, "robots", payload)
		case <-keepalive.C:
			writeSSE(w, flusher, "viewers", mustJSON(map[string]int{"viewers": hub.Viewers()}))
		}
	}
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, event string, payload []byte) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(w, "event: "+event+"\n")
	_, _ = io.WriteString(w, "data: ")
	_, _ = w.Write(payload)
	_, _ = io.WriteString(w, "\n\n")
	flusher.Flush()
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return raw
}

func listenUDP(addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			})
		},
	}
	return lc.ListenPacket(context.Background(), "udp4", addr)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackAuthority(r.Host) {
			http.Error(w, "loopback Host required", 403)
			return
		}
		origin := r.Header.Get("Origin")
		allowed := origin == ""
		if parsed, err := url.Parse(origin); err == nil && parsed.Scheme == "http" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && loopbackAuthority(parsed.Host) {
			allowed = parsed.Host == r.Host || origin == "http://127.0.0.1:3401" || origin == "http://localhost:3401"
		}
		if !allowed {
			http.Error(w, "browser origin has no LAN control authorization", 403)
			return
		}
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			w.Header().Set("Cache-Control", "no-cache")
		}
		if r.Method == http.MethodPost {
			contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || contentType != "application/json" {
				http.Error(w, "application/json required", 415)
				return
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loopbackAuthority(authority string) bool {
	host, _, err := net.SplitHostPort(authority)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
