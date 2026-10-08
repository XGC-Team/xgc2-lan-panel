package beacon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/XGC-Team/xgc2-lan-panel/internal/netinfo"
	"github.com/XGC-Team/xgc2-lan-panel/internal/nmapply"
	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
	"github.com/XGC-Team/xgc2-xrpc/go/httpx"
)

func TestSavedMetricDoesNotProveNativeDefaultRoute(t *testing.T) {
	request := protocol.ApplyRequest{Iface: "eth0", MakeDefault: true}
	plan, err := nmapply.BuildPlan(request, "ethernet", map[string]string{"eth0": "home", "eth1": "other"})
	if err != nil {
		t.Fatal(err)
	}
	var reapplied bool
	if err := nmapply.Run(func(args []string) (string, error) {
		if strings.Join(args, " ") == "device reapply eth1" {
			reapplied = true
		}
		return "", nil
	}, plan); err != nil {
		t.Fatal(err)
	}
	if !reapplied {
		t.Fatal("other active route metric was never applied")
	}
	metric := "10"
	opt := Options{Host: netinfo.Host{ReadFile: func(string) ([]byte, error) {
		return []byte("Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 010200C0 0003 0 0 50 00000000\neth1 00000000 010200C0 0003 0 0 " + metric + " 00000000\n"), nil
	}}, Nmcli: func(_ context.Context, args []string) (string, error) {
		if args[0] == "-g" {
			return "50", nil
		}
		return "GENERAL.STATE:100 (connected)\nGENERAL.CONNECTION:home\n", nil
	}}
	if err := verifyApplied(context.Background(), opt, request, plan); err == nil {
		t.Fatal("saved metric was mistaken for native route completion")
	}
	metric = "20600"
	if err := verifyApplied(context.Background(), opt, request, plan); err != nil {
		t.Fatal(err)
	}
}

func TestCallerCancellationAndUnknownNativeOutcomeRetainWriter(t *testing.T) {
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	opt := Options{Now: time.Now, Host: netinfo.Host{ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }, Hostname: func() (string, error) { return "robot", nil }, Interfaces: nil}, Nmcli: func(ctx context.Context, args []string) (string, error) {
		if args[0] == "-t" {
			return "home:eth0:ethernet", nil
		}
		if args[0] == "connection" && args[1] == "up" {
			close(entered)
			<-release
			if ctx.Err() != nil {
				t.Error("caller cancellation reached admitted native work")
			}
			return "", errors.New("native activation response lost")
		}
		return "", nil
	}}
	// The production Host maintains snapshots; avoid all OS collection here.
	opt.snapshots = &snapshotCache{beacon: protocol.Beacon{}, updated: time.Now()}
	handler := Handler(opt)
	request := func(id string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://robot/v1/apply", strings.NewReader(`{"iface":"eth0","address":"192.0.2.10/24","make_default":false}`))
		r.Header.Set(httpx.RequestIDHeader, id)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{RawSubjectPublicKeyInfo: []byte("operator")}}}
		return r
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(finished)
		handler.ServeHTTP(httptest.NewRecorder(), request("first").WithContext(ctx))
	}()
	<-entered
	cancel()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request("second"))
	if response.Code != 429 {
		t.Fatalf("cancelled caller freed actual native work: %d", response.Code)
	}
	close(release)
	<-finished
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request("third"))
	if response.Code != 429 {
		t.Fatalf("unknown native outcome freed writer: %d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request("first"))
	if response.Code != 500 || !strings.Contains(response.Body.String(), "outcome-unknown") {
		t.Fatalf("unknown receipt changed: %d %s", response.Code, response.Body.String())
	}
}
