package controltls

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
	xrpc "github.com/XGC-Team/xgc2-xrpc/go"
	"github.com/XGC-Team/xgc2-xrpc/go/httpx"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
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

func TestTargetGrantRejectsAnotherValidCAIdentityBeforeNativeEffect(t *testing.T) {
	_, ca, caKey := testIdentity(t, nil, nil, "test ca", x509.ExtKeyUsageAny)
	serverCert, _, _ := testIdentity(t, ca, caKey, "robot.example", x509.ExtKeyUsageServerAuth)
	clientCert, _, _ := testIdentity(t, ca, caKey, "operator", x509.ExtKeyUsageClientAuth)
	otherCert, _, _ := testIdentity(t, ca, caKey, "robot.example", x509.ExtKeyUsageServerAuth)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var effects atomic.Int64
	host, err := httpx.ServeTLS(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { effects.Add(1); w.WriteHeader(204) }), &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}, httpx.HostOptions{InstanceID: "boot-1"})
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
	ref := xrpc.ServiceRef{TargetID: "robot-1", Service: "xgc2.lan.v1.Beacon", APIVersion: "2", InstanceID: "boot-1", Profile: xrpc.HTTP, Endpoint: xrpc.Endpoint{Kind: "https", Address: "https://robot.example:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)}}
	base := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}}
	for _, fixture := range []struct {
		cert tls.Certificate
		want bool
	}{{otherCert, false}, {serverCert, true}} {
		hash := sha256.Sum256(fixture.cert.Leaf.RawSubjectPublicKeyInfo)
		grants := TargetGrants{"robot-1": {TargetID: "robot-1", ServerName: "robot.example", SPKI: hex.EncodeToString(hash[:])}}
		client, err := httpx.New(httpx.Config{LocalTargetID: "probe", Service: ref, TLSForService: func(ref xrpc.ServiceRef) (*tls.Config, error) { return grants.TLSForService(base, ref) }, DialContext: func(ctx context.Context, ref xrpc.ServiceRef) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, _, _, err = client.Do(ctx, http.MethodPost, "/v1/apply", "request-1", "application/json", []byte(`{}`))
		cancel()
		client.Close()
		if (err == nil) != fixture.want {
			t.Fatalf("valid=%v error=%v", fixture.want, err)
		}
		wrong := ref
		wrong.TargetID = "victim"
		if _, err := grants.TLSForService(base, wrong); err == nil {
			t.Fatal("UDP created a new target grant")
		}
		wrong = ref
		wrong.Endpoint.Address = "https://other.example:19519"
		if _, err := grants.TLSForService(base, wrong); err == nil {
			t.Fatal("UDP changed authorized server identity")
		}
	}
	if effects.Load() != 1 {
		t.Fatalf("ungranted server reached native effect: %d", effects.Load())
	}
}
