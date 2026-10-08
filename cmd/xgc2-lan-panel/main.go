package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/XGC-Team/xgc2-lan-panel/internal/beacon"
	"github.com/XGC-Team/xgc2-lan-panel/internal/controltls"
	"github.com/XGC-Team/xgc2-lan-panel/internal/probe"
	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
)

// version is set by -ldflags "-X main.version=..." from product.yml.
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	if wantsVersion(os.Args[1:]) {
		fmt.Println(version)
		return
	}
	cmd, args := resolveCommand(os.Args[0], os.Args[1:])
	switch cmd {
	case "beacon":
		os.Exit(runBeacon(args))
	case "probe":
		os.Exit(runProbe(args))
	case "help":
		usage()
	default:
		if cmd != "" {
			fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		}
		usage()
		os.Exit(2)
	}
}

func wantsVersion(args []string) bool {
	for _, arg := range args {
		if arg == "--version" || arg == "-version" {
			return true
		}
	}
	return false
}

func resolveCommand(argv0 string, args []string) (string, []string) {
	switch filepath.Base(argv0) {
	case "xgc2-lan-beacon":
		return "beacon", args
	case "xgc2-lan-probe":
		return "probe", args
	}
	if len(args) == 0 {
		return "", nil
	}
	switch args[0] {
	case "help", "-h", "--help":
		return "help", args[1:]
	default:
		return args[0], args[1:]
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `xgc2-lan-panel — field LAN robot finder (not Core/Agent)

Packages:
  xgc2-lan-beacon   robot; reply to solicits, authenticated HTTPS control on :%d
  xgc2-lan-probe    operator laptop; 2Hz solicit while a page is watching

  sudo apt install xgc2-lan-beacon    # robot
  sudo apt install xgc2-lan-probe     # laptop
  xgc2-lan-probe --tls-cert <file> --tls-key <file> --tls-ca <file> --beacon-grants <file>
  open http://127.0.0.1:%d/

The unified binary also accepts: xgc2-lan-panel beacon|probe
`, protocol.ControlPort, protocol.ProbePort)
}

func runBeacon(args []string) int {
	fs := flag.NewFlagSet("beacon", flag.ExitOnError)
	once := fs.Bool("once", false, "print one JSON snapshot and exit")
	control := fs.String("control", "", "authenticated HTTPS control listen address (default :19519)")
	cert := fs.String("tls-cert", os.Getenv("XGC2_LAN_TLS_CERT"), "deployment TLS certificate")
	key := fs.String("tls-key", os.Getenv("XGC2_LAN_TLS_KEY"), "deployment private key")
	ca := fs.String("tls-ca", os.Getenv("XGC2_LAN_TLS_CA"), "deployment CA trust bundle")
	name := fs.String("control-name", os.Getenv("XGC2_LAN_CONTROL_NAME"), "server certificate DNS name")
	callers := fs.String("control-callers", os.Getenv("XGC2_LAN_CONTROL_CALLERS"), "comma-separated granted caller SPKI SHA256 hashes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	opt := beacon.DefaultOptions()
	if *control != "" {
		opt.ControlAddr = *control
	}
	if *once {
		b, err := beacon.SnapshotOnce(opt)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(b)
		return 0
	}
	base, err := controltls.Load(controltls.Files{Certificate: *cert, Key: *key, CA: *ca})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	opt.TLSConfig, err = controltls.Server(base, strings.Split(*callers, ","))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	opt.ControlName = *name
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.SetPrefix("beacon ")
	log.Printf("listen solicit udp/%d; control %s", protocol.UDPPort, opt.ControlAddr)
	if err := beacon.Run(ctx, opt); err != nil && err != context.Canceled {
		log.Print(err)
		return 1
	}
	return 0
}

func runProbe(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	listen := fs.String("listen", fmt.Sprintf("127.0.0.1:%d", protocol.ProbePort), "UI and API listen address")
	udp := fs.String("udp", ":0", "UDP source for solicits (default ephemeral; robots listen :19518)")
	cert := fs.String("tls-cert", os.Getenv("XGC2_LAN_TLS_CERT"), "deployment TLS client certificate")
	key := fs.String("tls-key", os.Getenv("XGC2_LAN_TLS_KEY"), "deployment client private key")
	ca := fs.String("tls-ca", os.Getenv("XGC2_LAN_TLS_CA"), "deployment CA trust bundle")
	grantsPath := fs.String("beacon-grants", os.Getenv("XGC2_LAN_BEACON_GRANTS"), "deployment target to server DNS/SPKI authorization manifest")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	config, err := controltls.Load(controltls.Files{Certificate: *cert, Key: *key, CA: *ca})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	grants, err := controltls.LoadTargetGrants(*grantsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ui, err := uiFS()
	if err != nil {
		log.Printf("embedded UI missing (%v); API only", err)
		ui = nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.SetPrefix("probe ")
	if err := probe.Run(ctx, probe.Options{Listen: *listen, UDPAddr: *udp, UI: ui, TLSConfig: config, TargetGrants: grants}); err != nil && err != context.Canceled {
		log.Print(err)
		return 1
	}
	return 0
}

func uiFS() (fs.FS, error) {
	sub, err := fs.Sub(embeddedUI, "ui")
	if err != nil {
		return nil, err
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, err
	}
	return sub, nil
}
