package core

import (
	"fmt"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func BenchmarkGetStoredCredentials(b *testing.B) {
	setupPG(b)
	if err := PutUser(User{Username: "testuser"}); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := SaveWebAuthnCredential("testuser", &webauthn.Credential{ID: []byte(fmt.Sprintf("id-%d", i))}); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetStoredCredentials("testuser")
	}
}
