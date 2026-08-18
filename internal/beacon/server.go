package beacon

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/XGC-Team/xgc2-lan-panel/internal/netinfo"
	"github.com/XGC-Team/xgc2-lan-panel/internal/nmapply"
	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
	"golang.org/x/sys/unix"
)

type Options struct {
	UDPAddr     string
	ControlAddr string
	Host        netinfo.Host
	Nmcli       nmapply.Runner
	Now         func() time.Time
}

func DefaultOptions() Options {
	return Options{
		UDPAddr:     ":" + strconv.Itoa(protocol.UDPPort),
		ControlAddr: ":" + strconv.Itoa(protocol.ControlPort),
		Host:        netinfo.DefaultHost(),
		Nmcli: func(args []string) (string, error) {
			out, err := exec.Command("nmcli", args...).CombinedOutput()
			if err != nil {
				return string(out), err
			}
			return string(out), nil
		},
		Now: time.Now,
	}
}

func Run(ctx context.Context, opt Options) error {
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

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		b, err := snapshot(opt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, b)
	})
	mux.HandleFunc("POST /v1/apply", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.ApplyRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		log.Printf("apply iface=%s ssid=%s address=%s make_default=%v", req.Iface, req.SSID, req.Address, req.MakeDefault)
		result, status := apply(opt, req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(result)
	})

	srv := &http.Server{Addr: opt.ControlAddr, Handler: mux}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	pc, err := listenUDP(opt.UDPAddr)
	if err != nil {
		_ = srv.Close()
		return err
	}
	defer pc.Close()
	go replySolicits(ctx, pc, opt)

	log.Printf("wait for solicit on udp %s; control %s", opt.UDPAddr, opt.ControlAddr)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
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
	b, err := netinfo.Collect(opt.Host)
	if err != nil {
		return protocol.Beacon{}, err
	}
	b.TSUnixMS = opt.Now().UnixMilli()
	b.ControlPort = protocol.ControlPort
	b.V = protocol.Version
	b.Kind = protocol.Kind
	return b, nil
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

func apply(opt Options, req protocol.ApplyRequest) (protocol.ApplyResult, int) {
	if err := nmapply.Validate(req); err != nil {
		return protocol.ApplyResult{Message: err.Error()}, http.StatusBadRequest
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
	activeOut, _ := opt.Nmcli([]string{"-t", "-f", "NAME,DEVICE,TYPE", "connection", "show", "--active"})
	active := nmapply.ParseActiveConnections(activeOut)
	plan, err := nmapply.BuildPlan(req, kind, active)
	if err != nil {
		return protocol.ApplyResult{Message: err.Error()}, http.StatusBadRequest
	}
	if err := nmapply.Run(opt.Nmcli, plan); err != nil {
		return protocol.ApplyResult{Message: err.Error(), Warning: plan.Warning}, http.StatusInternalServerError
	}
	return protocol.ApplyResult{OK: true, Message: "applied", Warning: plan.Warning}, http.StatusOK
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
