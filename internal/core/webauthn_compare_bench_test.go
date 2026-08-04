package core

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

var benchmarkCredentialOrder int

func BenchmarkCompareStoredCredentials(b *testing.B) {
	a := StoredCredential{
		Credential: webauthn.Credential{ID: []byte("credential-a")},
		CreatedAt:  1,
	}
	bCredential := StoredCredential{
		Credential: webauthn.Credential{ID: []byte("credential-b")},
		CreatedAt:  1,
	}

	b.ReportAllocs()
	for b.Loop() {
		benchmarkCredentialOrder = compareStoredCredentials(a, bCredential)
	}
}
