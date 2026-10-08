package controltls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"

	xrpc "github.com/XGC-Team/xgc2-xrpc/go"
)

// TargetGrant is deployment authorization. UDP discovery cannot create it.
type TargetGrant struct {
	TargetID   string `json:"target_id"`
	ServerName string `json:"server_name"`
	SPKI       string `json:"spki_sha256"`
}
type TargetGrants map[string]TargetGrant

func LoadTargetGrants(path string) (TargetGrants, error) {
	raw, err := readRegular(path, 16<<10)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Schema  string        `json:"schema"`
		Targets []TargetGrant `json:"targets"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Schema != "xgc2.lan-control-grants/v1" || len(manifest.Targets) < 1 || len(manifest.Targets) > 64 {
		return nil, errors.New("invalid bounded LAN target authorization")
	}
	grants := make(TargetGrants, len(manifest.Targets))
	for _, grant := range manifest.Targets {
		if err := grant.validate(); err != nil {
			return nil, err
		}
		if _, exists := grants[grant.TargetID]; exists {
			return nil, errors.New("duplicate LAN target authorization")
		}
		grants[grant.TargetID] = grant
	}
	return grants, nil
}

func (grant TargetGrant) validate() error {
	hash, err := hex.DecodeString(grant.SPKI)
	if err != nil || len(hash) != sha256.Size || grant.SPKI != strings.ToLower(grant.SPKI) || len(grant.TargetID) < 1 || len(grant.TargetID) > 128 || strings.ContainsAny(grant.TargetID, " \t\r\n\x00") || len(grant.ServerName) < 1 || len(grant.ServerName) > 253 || grant.ServerName != strings.ToLower(grant.ServerName) || net.ParseIP(grant.ServerName) != nil || strings.ContainsAny(grant.ServerName, ":/\\@ \t\r\n\x00") {
		return errors.New("invalid LAN target identity grant")
	}
	return nil
}

func (grants TargetGrants) TLSForService(base *tls.Config, ref xrpc.ServiceRef) (*tls.Config, error) {
	grant, ok := grants[ref.TargetID]
	if !ok || grant.validate() != nil {
		return nil, errors.New("LAN target has no control grant")
	}
	endpoint, err := url.Parse(ref.Endpoint.Address)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Hostname() != grant.ServerName || ref.Service != "xgc2.lan.v1.Beacon" || ref.APIVersion != "2" {
		return nil, errors.New("discovered LAN identity does not match target authorization")
	}
	if base == nil || base.InsecureSkipVerify || base.RootCAs == nil || len(base.Certificates) != 1 {
		return nil, errors.New("LAN client TLS identity required")
	}
	config := base.Clone()
	config.ServerName = grant.ServerName
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("verified LAN server required")
		}
		hash := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if hex.EncodeToString(hash[:]) != grant.SPKI {
			return errors.New("LAN server key does not match target authorization")
		}
		return nil
	}
	return config, nil
}
