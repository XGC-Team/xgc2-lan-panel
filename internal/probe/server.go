package probe

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
	"golang.org/x/sys/unix"
)

type Options struct {
	Listen  string
	UDPAddr string
	UI      fs.FS
	Client  *http.Client
	Now     func() time.Time
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
	if opt.Client == nil {
		opt.Client = &http.Client{Timeout: 45 * time.Second}
	}
	reg := NewRegistry(opt.Now)
	hub := NewHub()
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

	go readBeacons(ctx, pc, reg, hub, publish)
	go staleTicker(ctx, hub, publish)
	go solicitLoop(ctx, pc, hub)

	mux := http.NewServeMux()
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
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		url := "http://" + net.JoinHostPort(row.ReachIP, strconv.Itoa(row.Beacon.ControlPort)) + "/v1/apply"
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, strings.NewReader(string(body)))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := opt.Client.Do(req)
		if err != nil {
			writeJSONStatus(w, http.StatusBadGateway, protocol.ApplyResult{
				Message: err.Error(),
				Warning: "the robot may be switching networks; wait for it to reappear",
			})
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
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

	srv := &http.Server{Addr: opt.Listen, Handler: withCORS(mux)}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("probe ui/api on http://%s  (solicit %s → :%d)", opt.Listen, pc.LocalAddr(), protocol.UDPPort)
	err = srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
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
		origin := r.Header.Get("Origin")
		if origin == "http://127.0.0.1:3401" || origin == "http://localhost:3401" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			w.Header().Set("Cache-Control", "no-cache")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
