// Package controltls validates the explicit deployment identity and caller grant.
// It does not generate credentials or discover a product-specific data root.
package controltls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

type Files struct{ Certificate, Key, CA string }

func Load(files Files) (*tls.Config, error) {
	if files.Certificate == "" || files.Key == "" || files.CA == "" {
		return nil, errors.New("LAN control needs explicit certificate, private key and CA files")
	}
	certificate, err := readRegular(files.Certificate, 64<<10)
	if err != nil {
		return nil, err
	}
	key, err := readRegularWithMode(files.Key, 16<<10, true)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return nil, errors.New("cannot load LAN TLS identity")
	}
	raw, err := readRegular(files.CA, 64<<10)
	if err != nil {
		return nil, errors.New("cannot load LAN TLS trust bundle")
	}
	if len(raw) > 64<<10 {
		return nil, errors.New("LAN CA bundle exceeds byte budget")
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(raw) {
		return nil, errors.New("invalid LAN TLS trust bundle")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, RootCAs: ca, ClientCAs: ca}, nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	return readRegularWithMode(path, limit, false)
}
func readRegularWithMode(path string, limit int64, private bool) ([]byte, error) {
	if path == "" {
		return nil, errors.New("explicit identity or grant path required")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open deployment identity or grant")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("deployment identity or grant exceeds regular-file budget")
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 || stat.Nlink != 1 {
			return nil, errors.New("private LAN key requires an owned single-link mode 0600 grant")
		}
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("deployment identity or grant exceeds byte budget")
	}
	return raw, nil
}
func Server(base *tls.Config, callers []string) (*tls.Config, error) {
	if base == nil || base.ClientCAs == nil || len(base.Certificates) != 1 {
		return nil, errors.New("LAN server TLS identity and CA required")
	}
	if len(callers) == 0 || len(callers) > 64 {
		return nil, errors.New("LAN control requires a bounded explicit caller grant")
	}
	grants := make(map[string]bool, len(callers))
	for _, caller := range callers {
		raw, err := hex.DecodeString(caller)
		if err != nil || len(raw) != sha256.Size || caller != strings.ToLower(caller) {
			return nil, errors.New("caller grant must be canonical SHA256 of certificate SPKI")
		}
		grants[caller] = true
	}
	config := base.Clone()
	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("authenticated LAN caller required")
		}
		hash := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if !grants[hex.EncodeToString(hash[:])] {
			return errors.New("LAN caller has no control grant")
		}
		return nil
	}
	return config, nil
}
