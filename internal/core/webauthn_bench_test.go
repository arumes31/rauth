package core

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

func BenchmarkGetStoredCredentialsFallback(b *testing.B) {
	mr, err := miniredis.Run()
	if err != nil {
		b.Fatal(err)
	}
	defer mr.Close()

	UserDB = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	Ctx = context.Background()

	listKey := "user:testuser:webauthn_creds"

	creds := make([]StoredCredential, 100)
	for i := 0; i < 100; i++ {
		creds[i] = StoredCredential{
			Credential: webauthn.Credential{
				ID: []byte(fmt.Sprintf("id-%d", i)),
			},
			Nickname: fmt.Sprintf("cred-%d", i),
		}
		data, _ := json.Marshal(creds[i])
		UserDB.RPush(Ctx, listKey, string(data))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetStoredCredentials("testuser")

		// Reset state
		b.StopTimer()
		UserDB.Del(Ctx, "user:testuser:webauthn_creds_v2")
		// Refill the list key if the test consumed it
		UserDB.Del(Ctx, listKey)
		for _, c := range creds {
			data, _ := json.Marshal(c)
			UserDB.RPush(Ctx, listKey, string(data))
		}
		b.StartTimer()
	}
}
