package clustertransport

import (
	"crypto"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"time"
)

func certificateLeaf(pair tls.Certificate) (*x509.Certificate, error) {
	if len(pair.Certificate) == 0 || pair.PrivateKey == nil {
		return nil, ErrConfiguration
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, ErrConfiguration
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, ErrConfiguration
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || subtle.ConstantTimeCompare(public, leaf.RawSubjectPublicKeyInfo) != 1 {
		return nil, ErrConfiguration
	}
	return leaf, nil
}

// verifyOwnChain includes the supplied TLS chain, while retaining the explicit
// root trust pool. Supplying an intermediate never promotes it to a trust root.
func verifyOwnChain(pair tls.Certificate, leaf *x509.Certificate, roots *x509.CertPool, usage x509.ExtKeyUsage) error {
	if len(pair.Certificate) > 8 {
		return ErrConfiguration
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return ErrConfiguration
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return ErrConfiguration
	}
	return nil
}

// ServerTLS requires a private CA and certificate with the exact local node URI.
// Permissions/revocation are checked again by Gate on EVERY HTTP request, not
// merely at the connection's handshake. The caller owns immutable key material.
func ServerTLS(pair tls.Certificate, roots *x509.CertPool, cluster, self string) (*tls.Config, error) {
	if roots == nil || !validID(cluster) || !validID(self) {
		return nil, ErrConfiguration
	}
	leaf, err := certificateLeaf(pair)
	if err != nil {
		return nil, err
	}
	own, err := identity(leaf, cluster, time.Now())
	if err != nil || own.NodeID != self {
		return nil, ErrConfiguration
	}
	if err = verifyOwnChain(pair, leaf, roots, x509.ExtKeyUsageServerAuth); err != nil {
		return nil, ErrConfiguration
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots.Clone(), VerifyConnection: func(state tls.ConnectionState) error { _, err := peerFromTLS(state, cluster, time.Now()); return err }}, nil
}

// ClientTLS verifies the private CA, TLS hostname, exact server node URI and
// 1-2 enrolled public-key pins. Two pins permit controlled rotation overlap.
// A valid certificate from another enrolled node cannot replace the controller.
func ClientTLS(pair tls.Certificate, roots *x509.CertPool, serverName, cluster, selfNode, serverNode string, pins [][32]byte) (*tls.Config, error) {
	if roots == nil || serverName == "" || !validID(cluster) || !validID(selfNode) || !validID(serverNode) || len(pins) < 1 || len(pins) > 2 {
		return nil, ErrConfiguration
	}
	leaf, err := certificateLeaf(pair)
	if err != nil {
		return nil, err
	}
	own, err := identity(leaf, cluster, time.Now())
	if err != nil || own.NodeID != selfNode {
		return nil, ErrConfiguration
	}
	if err = verifyOwnChain(pair, leaf, roots, x509.ExtKeyUsageClientAuth); err != nil {
		return nil, ErrConfiguration
	}
	allowed := append([][32]byte(nil), pins...)
	for i, pin := range allowed {
		if pin == ([32]byte{}) || (i > 0 && pin == allowed[0]) {
			return nil, ErrConfiguration
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots.Clone(), Certificates: []tls.Certificate{pair}, VerifyConnection: func(state tls.ConnectionState) error {
		peer, err := peerFromTLS(state, cluster, time.Now())
		if err != nil || peer.NodeID != serverNode {
			return ErrIdentity
		}
		for _, pin := range allowed {
			if subtle.ConstantTimeCompare(pin[:], peer.SPKI[:]) == 1 {
				return nil
			}
		}
		return ErrIdentity
	}}, nil
}
