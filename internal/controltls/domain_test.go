package controltls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	xrpc "github.com/XGC-Team/xgc2-xrpc/go"
)

func TestTargetAuthorizationParsesAnOwnedSnapshotWithoutFileIO(t *testing.T) {
	target := TargetGrant{TargetID: "robot-1", ServerName: "robot.example", SPKI: strings.Repeat("a", 64)}
	encode := func(targets []TargetGrant) []byte {
		raw, err := json.Marshal(map[string]any{"schema": "xgc2.lan-control-grants/v1", "targets": targets})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if grants, err := ParseTargetGrants(encode([]TargetGrant{target})); err != nil || grants[target.TargetID] != target {
		t.Fatalf("domain snapshot lost target identity: %v %v", grants, err)
	}
	invalid := target
	invalid.TargetID = "robot/another"
	for _, raw := range [][]byte{
		nil,
		[]byte(strings.Repeat(" ", 16<<10+1)),
		encode(nil),
		encode([]TargetGrant{target, target}),
		encode([]TargetGrant{invalid}),
		[]byte(`{"schema":"xgc2.lan-control-grants/v1","targets":[],"tls_key":"implicit.pem"}`),
		append(encode([]TargetGrant{target}), []byte(` {}`)...),
	} {
		if grants, err := ParseTargetGrants(raw); err == nil || grants != nil {
			t.Fatal("invalid domain authorization accepted")
		}
	}
}

func TestDiscoveredReferenceCannotChangeAuthorizedServiceOrOmitFence(t *testing.T) {
	grants := TargetGrants{"robot-1": {TargetID: "robot-1", ServerName: "robot.example", SPKI: strings.Repeat("a", 64)}}
	ref := xrpc.ServiceRef{TargetID: "robot-1", Service: "xgc2.lan.v1.Beacon", APIVersion: "2", Profile: xrpc.HTTP, InstanceID: "boot-1", Endpoint: xrpc.Endpoint{Kind: "https", Address: "https://robot.example:19519"}}
	if _, err := grants.CheckService(ref); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*xrpc.ServiceRef){
		func(r *xrpc.ServiceRef) { r.InstanceID = "" },
		func(r *xrpc.ServiceRef) { r.TargetID = "ungranted" },
		func(r *xrpc.ServiceRef) { r.Service = "other.Service" },
		func(r *xrpc.ServiceRef) { r.APIVersion = "1" },
		func(r *xrpc.ServiceRef) { r.Profile = xrpc.GRPC },
		func(r *xrpc.ServiceRef) { r.Endpoint.Address += "/v1/apply" },
		func(r *xrpc.ServiceRef) { r.Endpoint.Address += "?target=robot-1" },
		func(r *xrpc.ServiceRef) { r.Endpoint.Address += "#ignored" },
		func(r *xrpc.ServiceRef) { r.Endpoint.Address = "https://other.example:19519" },
	} {
		wrong := ref
		change(&wrong)
		if _, err := grants.CheckService(wrong); err == nil {
			t.Fatal("untrusted discovery changed service authorization")
		}
	}
}

func TestCallerAuthorizationRequiresVerifiedCertificateAndBoundedUniqueGrant(t *testing.T) {
	leaf := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("granted-native-identity")}
	hash := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	caller := hex.EncodeToString(hash[:])
	grants, err := ParseCallerGrants([]string{caller})
	if err != nil {
		t.Fatal(err)
	}
	verified := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	if err := grants.VerifyCaller(verified); err != nil {
		t.Fatal(err)
	}
	verified.VerifiedChains = nil
	if err := grants.VerifyCaller(verified); err == nil {
		t.Fatal("SPKI grant replaced native certificate verification")
	}
	for _, callers := range [][]string{nil, {caller, caller}, {strings.ToUpper(caller)}, {"bad"}, make([]string, 65)} {
		if grants, err := ParseCallerGrants(callers); err == nil || grants != nil {
			t.Fatal("invalid caller authorization accepted")
		}
	}
}

func TestDomainGrantDoesNotReplaceExistingTransportPeerVerifier(t *testing.T) {
	leaf := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("granted-native-identity")}
	hash := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	spki := hex.EncodeToString(hash[:])
	rejected := errors.New("existing transport owner rejected peer")
	base := &tls.Config{RootCAs: x509.NewCertPool(), ClientCAs: x509.NewCertPool(), Certificates: []tls.Certificate{{}}, VerifyConnection: func(tls.ConnectionState) error { return rejected }}
	server, err := Server(base, []string{spki})
	if err != nil || !errors.Is(server.VerifyConnection(tls.ConnectionState{}), rejected) {
		t.Fatal("caller domain grant replaced transport verification")
	}
	ref := xrpc.ServiceRef{TargetID: "robot-1", Service: "xgc2.lan.v1.Beacon", APIVersion: "2", Profile: xrpc.HTTP, InstanceID: "boot-1", Endpoint: xrpc.Endpoint{Kind: "https", Address: "https://robot.example:19519"}}
	grants := TargetGrants{"robot-1": {TargetID: "robot-1", ServerName: "robot.example", SPKI: spki}}
	client, err := grants.TLSForService(base, ref)
	if err != nil || !errors.Is(client.VerifyConnection(tls.ConnectionState{}), rejected) {
		t.Fatal("target domain grant replaced transport verification")
	}
}
