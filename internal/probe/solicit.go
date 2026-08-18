package probe

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/XGC-Team/xgc2-lan-panel/internal/netinfo"
	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
)

func solicitLoop(ctx context.Context, conn net.PacketConn, hub *Hub) {
	tick := time.NewTicker(protocol.SolicitEvery)
	defer tick.Stop()
	wasViewing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if !hub.Viewing() {
				if wasViewing {
					log.Printf("no viewers; solicit off")
					wasViewing = false
				}
				continue
			}
			if !wasViewing {
				log.Printf("viewers present; solicit 2Hz on every local segment")
				wasViewing = true
			}
			sendSolicits(conn)
		}
	}
}

func sendSolicits(conn net.PacketConn) {
	raw, err := protocol.MarshalSolicit()
	if err != nil {
		return
	}
	port := protocol.UDPPort
	for _, dest := range netinfo.SolicitTargets(netinfo.ListLocalIPv4()) {
		addr := &net.UDPAddr{IP: dest, Port: port}
		if _, err := conn.WriteTo(raw, addr); err != nil {
			log.Printf("solicit %s: %v", dest, err)
		}
	}
}
