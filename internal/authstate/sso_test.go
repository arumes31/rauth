package authstate_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/authstate"
)

func TestSSOExactOriginAndLocalReturn(t *testing.T) {
	for _, s := range []string{"https://app.example.com", "https://xn--bcher-kva.example"} {
		assert.True(t, authstate.SSOOrigin(s), s)
	}
	for _, s := range []string{"http://app.example.com", "https://*.example.com", "https://APP.example.com", "https://app.example.com/", "https://app.example.com:443", "https://app.example.com?", "https://u@app.example.com", "https://127.0.0.1", "https://[::1]", "https://app.example.com.", "https://app.example.com/#foo"} {
		assert.False(t, authstate.SSOOrigin(s), s)
	}
	for _, s := range []string{"/", "/remote.php/dav/files/a/opaque%253bname;v=1?x=%25%3B", "/docs?q=https://example.org", "/page#part"} {
		assert.True(t, authstate.SSOLocalReturn(s), s)
	}
	for _, s := range []string{"", "https://evil.test", "//evil.test", "/\\evil.test", "/%2fevil.test", "/%5cevil.test", "/x\r\nLocation: bad", "/%0dfoo", "/_rauth/callback", "/path/../_rauth/start", "/%5frauth/callback", strings.Repeat("/", 4097)} {
		assert.False(t, authstate.SSOLocalReturn(s), s)
	}
}
func TestSSOCrossNodeAudienceRotationAndGlobalLogout(t *testing.T) {
	p, a, b := fixture(t)
	ctx := context.Background()
	central, app, next := token("central"), token("app"), token("next-app")
	require.NoError(t, a.Issue(ctx, central, params()))
	tx, browser, code := token("tx"), token("browser"), token("code")
	const origin = "https://app.other.test"
	const local = "/remote.php/dav/files/a/test%253b;v?x=%25"
	require.NoError(t, a.BeginSSO(ctx, tx, browser, origin, local))
	target, err := b.AuthorizeSSO(ctx, tx, code, central)
	require.NoError(t, err)
	assert.Equal(t, origin, target)
	_, err = a.RedeemSSO(ctx, tx, code, token("wrong-browser"), origin, app, time.Hour)
	require.Error(t, err)
	_, err = a.RedeemSSO(ctx, tx, code, browser, "https://wrong.other.test", app, time.Hour)
	require.Error(t, err)
	_, err = a.RedeemSSO(ctx, tx, token("wrong-code"), browser, origin, app, time.Hour)
	require.Error(t, err)
	returned, err := b.RedeemSSO(ctx, tx, code, browser, origin, app, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, local, returned)
	_, err = a.RedeemSSO(ctx, tx, code, browser, origin, token("replay"), time.Hour)
	require.Error(t, err)
	root, err := a.Get(ctx, central)
	require.NoError(t, err)
	child, err := a.Get(ctx, app)
	require.NoError(t, err)
	assert.Equal(t, root.FamilyID, child.FamilyID)
	assert.Equal(t, origin, child.Audience)
	assert.Empty(t, root.Audience)
	assert.True(t, root.AbsoluteExpiresAt.Equal(child.AbsoluteExpiresAt))
	ok, err := a.Rotate(ctx, app, next, 20*time.Minute, 30*time.Second)
	require.NoError(t, err)
	require.True(t, ok)
	child, err = b.Get(ctx, next)
	require.NoError(t, err)
	assert.Equal(t, origin, child.Audience)
	require.NoError(t, a.BeginSSO(ctx, token("app-tx"), browser, origin, "/"))
	_, err = b.AuthorizeSSO(ctx, token("app-tx"), token("app-code"), next)
	require.Error(t, err, "an app cookie cannot mint an SSO authorization")
	// A logout through an old grace alias reaches the root and every linked app.
	require.NoError(t, b.Revoke(ctx, app))
	for _, tok := range []string{central, app, next} {
		_, err = a.Get(ctx, tok)
		require.ErrorIs(t, err, authstate.ErrNotFound)
	}
	var raw string
	require.NoError(t, p.QueryRow(ctx, "SELECT payload::text FROM auth_sso_transactions LIMIT 1").Scan(&raw))
	for _, secret := range []string{tx, browser, code, local, central, app} {
		assert.NotContains(t, raw, secret)
	}
}
func TestSSORedemptionIsAtomicAcrossNodes(t *testing.T) {
	_, a, b := fixture(t)
	ctx := context.Background()
	root := token("root")
	require.NoError(t, a.Issue(ctx, root, params()))
	tx, browser, code := token("transaction"), token("browser"), token("code")
	const origin = "https://app.example.org"
	require.NoError(t, a.BeginSSO(ctx, tx, browser, origin, "/"))
	_, err := a.AuthorizeSSO(ctx, tx, code, root)
	require.NoError(t, err)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			node := a
			if i%2 == 0 {
				node = b
			}
			_, err := node.RedeemSSO(ctx, tx, code, browser, origin, token(string(rune('a'+i))), time.Minute)
			if err == nil {
				successes.Add(1)
			}
		}(i)
	}
	wg.Wait()
	assert.EqualValues(t, 1, successes.Load())
}
func TestSSOExpiryRevocationAndRollback(t *testing.T) {
	for _, mode := range []string{"code-expired", "transaction-expired", "logout", "credential-change", "restamp", "insert-conflict"} {
		t.Run(mode, func(t *testing.T) {
			p, a, b := fixture(t)
			ctx := context.Background()
			root, app := token("root"), token("app")
			require.NoError(t, a.Issue(ctx, root, params()))
			tx, browser, code := token("tx"), token("browser"), token("code")
			const origin = "https://app.example.org"
			require.NoError(t, a.BeginSSO(ctx, tx, browser, origin, "/"))
			_, err := b.AuthorizeSSO(ctx, tx, code, root)
			require.NoError(t, err)
			switch mode {
			case "code-expired":
				_, err = p.Exec(ctx, "UPDATE auth_sso_transactions SET code_expires_at=clock_timestamp()-interval '1 second'")
			case "transaction-expired":
				_, err = p.Exec(ctx, "UPDATE auth_sso_transactions SET expires_at=clock_timestamp()-interval '1 second'")
			case "logout":
				err = a.Revoke(ctx, root)
			case "credential-change":
				err = a.RevokeUser(ctx, "alice")
			case "restamp":
				_, err = p.Exec(ctx, "UPDATE auth_generations SET gen=1 WHERE username='alice'")
				require.NoError(t, err)
				var ok bool
				ok, err = a.Restamp(ctx, root, 0, 1)
				require.True(t, ok)
			case "insert-conflict":
				app = root
			}
			require.NoError(t, err)
			_, err = b.RedeemSSO(ctx, tx, code, browser, origin, app, time.Minute)
			require.Error(t, err)
			if mode == "insert-conflict" {
				_, err = b.RedeemSSO(ctx, tx, code, browser, origin, token("fresh"), time.Minute)
				require.NoError(t, err, "a failed insertion must not consume the code")
			}
		})
	}
}
