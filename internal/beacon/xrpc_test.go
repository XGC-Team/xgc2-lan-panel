package beacon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XGC-Team/xgc2-lan-panel/internal/controltls"
	"github.com/XGC-Team/xgc2-lan-panel/internal/netinfo"
	"github.com/XGC-Team/xgc2-lan-panel/internal/protocol"
	xrpc "github.com/XGC-Team/xgc2-xrpc/go"
	"github.com/XGC-Team/xgc2-xrpc/go/httpx"
)

func testIdentity(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, name string, usage x509.ExtKeyUsage) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{name}}
	if parent == nil {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage |= x509.KeyUsageCertSign
		parent = template
		parentKey = key
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key, Leaf: leaf}, leaf, key
}

func TestAuthenticatedControlIsFencedDeduplicatedAndNative(t *testing.T) {
	_, ca, caKey := testIdentity(t, nil, nil, "LAN Test CA", x509.ExtKeyUsageAny)
	serverCert, _, _ := testIdentity(t, ca, caKey, "robot.example", x509.ExtKeyUsageServerAuth)
	clientCert, _, _ := testIdentity(t, ca, caKey, "operator", x509.ExtKeyUsageClientAuth)
	otherCert, _, _ := testIdentity(t, ca, caKey, "ungranted", x509.ExtKeyUsageClientAuth)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	hash := sha256.Sum256(clientCert.Leaf.RawSubjectPublicKeyInfo)
	serverTLS, err := controltls.Server(&tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots}, []string{hex.EncodeToString(hash[:])})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var effects atomic.Int64
	var correct atomic.Bool
	correct.Store(true)
	opt := Options{InstanceID: "new-boot", ControlName: "robot.example", ControlPort: listener.Addr().(*net.TCPAddr).Port, Now: time.Now, Host: netinfo.Host{
		ReadFile: func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "machine-id") {
				return []byte("robot1"), nil
			}
			return nil, os.ErrNotExist
		},
		ReadDir: func(string) ([]os.DirEntry, error) { return nil, nil }, Stat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }, Hostname: func() (string, error) { return "robot.example", nil }, Interfaces: func() ([]net.Interface, error) { return nil, nil },
	}, Nmcli: func(ctx context.Context, args []string) (string, error) {
		if args[0] == "-t" && args[len(args)-1] == "--active" {
			return "home:eth0:ethernet", nil
		}
		if args[0] == "-t" {
			address := "192.0.2.10/24"
			if !correct.Load() {
				address = "192.0.2.99/24"
			}
			return "GENERAL.STATE:100 (connected)\nGENERAL.CONNECTION:home\nIP4.ADDRESS[1]:" + address + "\n", nil
		}
		if args[0] == "connection" && args[1] == "up" {
			effects.Add(1)
		}
		return "", nil
	}}
	host, err := httpx.ServeTLS(listener, Handler(opt), serverTLS, httpx.HostOptions{InstanceID: opt.InstanceID, DiscoveryPaths: []string{"/v1/describe"}, MaxBodyBytes: 1 << 16, MaxConnections: 4, MaxInFlight: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := host.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	}()
	service := xrpc.ServiceRef{TargetID: "robot1", Service: "xgc2.lan.v1.Beacon", APIVersion: "2", Profile: xrpc.HTTP, InstanceID: opt.InstanceID, Endpoint: xrpc.Endpoint{Kind: "https", Address: "https://robot.example:" + strconv.Itoa(opt.ControlPort)}}
	makeClient := func(cert *tls.Certificate, instance string) *httpx.Client {
		ref := service
		ref.InstanceID = instance
		config := &tls.Config{RootCAs: roots, ServerName: "robot.example"}
		if cert != nil {
			config.Certificates = []tls.Certificate{*cert}
		}
		c, err := httpx.New(httpx.Config{LocalTargetID: "probe", Service: ref, TLSConfig: config, DialContext: func(ctx context.Context, ref xrpc.ServiceRef) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		return c
	}
	payload := []byte(`{"iface":"eth0","address":"192.0.2.10/24","make_default":false}`)
	call := func(client *httpx.Client, id string) ([]byte, int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		raw, status, _, err := client.Do(ctx, http.MethodPost, "/v1/apply", id, "application/json", payload)
		return raw, status, err
	}
	for name, cert := range map[string]*tls.Certificate{"anonymous": nil, "no-grant": &otherCert} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := call(makeClient(cert, opt.InstanceID), name); err == nil {
				t.Fatal("unauthorized control admitted")
			}
		})
	}
	if effects.Load() != 0 {
		t.Fatal("auth rejection caused native effect")
	}
	if _, status, err := call(makeClient(&clientCert, "old-boot"), "stale"); err == nil || status != 0 {
		t.Fatalf("stale reference accepted: %d %v", status, err)
	}
	if effects.Load() != 0 {
		t.Fatal("stale instance caused native effect")
	}
	client := makeClient(&clientCert, opt.InstanceID)
	raw, status, err := call(client, "native-1")
	if err != nil || status != 200 {
		t.Fatalf("native control failed: %d %s %v", status, raw, err)
	}
	var result protocol.ApplyResult
	if err := json.Unmarshal(raw, &result); err != nil || !result.OK || !result.Applied || !result.Persisted {
		t.Fatalf("missing completion facts: %s %v", raw, err)
	}
	if _, status, err := call(client, "native-1"); err != nil || status != 200 || effects.Load() != 1 {
		t.Fatalf("request replay caused another effect: %d %v effects=%d", status, err, effects.Load())
	}
	correct.Store(false)
	raw, status, err = call(client, "native-2")
	if err != nil || status != 409 {
		t.Fatalf("wrong native state reported success: %d %s %v", status, raw, err)
	}
	if err = json.Unmarshal(raw, &result); err != nil || result.OK || !result.PartialEffects || result.FailureStage != "postcondition" {
		t.Fatalf("partial failure facts missing: %s %v", raw, err)
	}
}
