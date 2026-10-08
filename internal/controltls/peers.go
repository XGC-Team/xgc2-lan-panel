package controltls

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"strings"
)

// CallerGrants is LAN method authorization, separate from native certificate
// loading and common transport authentication. Discovery cannot change it.
type CallerGrants map[string]struct{}

func ParseCallerGrants(callers []string) (CallerGrants, error) {
	if len(callers) == 0 || len(callers) > 64 {
		return nil, errors.New("LAN control requires a bounded explicit caller grant")
	}
	grants := make(CallerGrants, len(callers))
	for _, caller := range callers {
		raw, err := hex.DecodeString(caller)
		if err != nil || len(raw) != sha256.Size || caller != strings.ToLower(caller) {
			return nil, errors.New("caller grant must be canonical SHA256 of certificate SPKI")
		}
		if _, exists := grants[caller]; exists {
			return nil, errors.New("duplicate LAN caller authorization")
		}
		grants[caller] = struct{}{}
	}
	return grants, nil
}

func (grants CallerGrants) VerifyCaller(state tls.ConnectionState) error {
	if len(grants) < 1 || len(grants) > 64 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return errors.New("authenticated LAN caller required")
	}
	hash := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if _, allowed := grants[hex.EncodeToString(hash[:])]; !allowed {
		return errors.New("LAN caller has no control grant")
	}
	return nil
}
