package core

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"rauth/internal/authstate"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sqlSecurityFixture(t *testing.T) {
	t.Helper()
	newRegressionRedis(t)
	k, err := authstate.NewKeyring(strings.Repeat("index-test-key-", 3), "v1", map[string]string{"v1": strings.Repeat("payload-test-", 3)})
	require.NoError(t, err)
	s, err := authstate.NewPostgresSessions(Ctx, PG, k)
	require.NoError(t, err)
	securityArtifacts = s.Artifacts()
	securityCounters = s.Counters()
	// These paths must use the selected SQL authority without any Redis client.
	TokenDB = nil
	RateLimitDB = nil
	InviteDB = nil
}
func TestSQLArtifactsCoreFlowsWithoutRedis(t *testing.T) {
	sqlSecurityFixture(t)
	SetBcryptCost(4)
	t.Cleanup(func() { SetBcryptCost(12) })
	require.NoError(t, CreateUser("enroll-user", "Password123", "", false, ""))
	gen := currentGen(t, "enroll-user")
	id := strings.Repeat("a", 64)
	require.NoError(t, StoreAuthArtifact(PendingEnrollment, id, []byte(PendingTokenValue("enroll-user", gen)), "enroll-user", gen, 10*time.Minute))
	secret, err := EnrollmentSecretValue(id, "enroll-user", gen, "ORIGINALSECRET")
	require.NoError(t, err)
	assert.Equal(t, "ORIGINALSECRET", secret)
	secret, err = EnrollmentSecretValue(id, "enroll-user", gen, "REPLACEMENT")
	require.NoError(t, err)
	assert.Equal(t, "ORIGINALSECRET", secret)
	encrypted, err := Encrypt2FASecret("ORIGINALSECRET", ServerSecret)
	require.NoError(t, err)
	ok, err := CompleteSecondFactorEnrollment(id, "enroll-user", gen, encrypted)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = CompleteSecondFactorEnrollment(id, "enroll-user", gen, encrypted)
	require.NoError(t, err)
	assert.False(t, ok)
	_, err = GetAuthArtifact(EnrollmentSecret, id)
	require.ErrorIs(t, err, ErrAuthArtifactMissing)
	u, err := GetUser("enroll-user")
	require.NoError(t, err)
	assert.Equal(t, "ORIGINALSECRET", Decrypt2FASecret(u.TwoFactor, ServerSecret))
	assert.True(t, CheckRateLimit("shared-test", 2, 60))
	assert.True(t, CheckRateLimit("shared-test", 2, 60))
	assert.False(t, CheckRateLimit("shared-test", 2, 60))
	assert.True(t, IsRateLimitExceeded("shared-test", 2))
	ResetRateLimit("shared-test")
	assert.False(t, IsRateLimitExceeded("shared-test", 2))
	assert.False(t, TOTPCodeReused("enroll-user", " 123456 "))
	assert.True(t, TOTPCodeReused("enroll-user", "123456"))
}
func TestSQLInvitationAccountAndClaimCommitTogether(t *testing.T) {
	sqlSecurityFixture(t)
	SetBcryptCost(4)
	t.Cleanup(func() { SetBcryptCost(12) })
	require.NoError(t, CreateUser("existing", "Password123", "", false, ""))
	id := strings.Repeat("b", 64)
	require.NoError(t, StoreAuthArtifact(Invitation, id, []byte("invite@example.com"), "", "", 24*time.Hour))
	require.ErrorIs(t, RedeemInvitation(id, "existing", "Password123"), errUserExists)
	_, err := GetAuthArtifact(Invitation, id)
	require.NoError(t, err, "failed account claim must leave the invitation usable")
	var wg sync.WaitGroup
	var wins atomic.Int32
	gate := make(chan struct{})
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate
			err := RedeemInvitation(id, "invited"+string(rune('a'+i)), "Password123")
			if err == nil {
				wins.Add(1)
			} else {
				assert.ErrorIs(t, err, ErrAuthArtifactMissing)
			}
		}(i)
	}
	close(gate)
	wg.Wait()
	assert.Equal(t, int32(1), wins.Load())
	var count int
	require.NoError(t, PG.QueryRow(Ctx, "SELECT count(*) FROM users WHERE email='invite@example.com'").Scan(&count))
	assert.Equal(t, 1, count)
	_, err = GetAuthArtifact(Invitation, id)
	require.ErrorIs(t, err, ErrAuthArtifactMissing)
}
func TestLegacyArtifactAtomicTakeAndGenerationBinding(t *testing.T) {
	newRegressionRedis(t)
	require.NoError(t, CreateUser("pending-user", "Password123", "", false, ""))
	gen := currentGen(t, "pending-user")
	id := strings.Repeat("c", 64)
	require.NoError(t, StoreAuthArtifact(PendingSecondFactor, id, []byte(PendingTokenValue("pending-user", gen)), "pending-user", gen, time.Minute))
	raw, err := TokenDB.Get(Ctx, "pending_2fa:"+id).Result()
	require.NoError(t, err)
	assert.Equal(t, PendingTokenValue("pending-user", gen), raw, "legacy fixtures and rolling drain can still read the payload")
	_, err = TakeAuthArtifact(PendingSecondFactor, id)
	require.NoError(t, err)
	_, err = TakeAuthArtifact(PendingSecondFactor, id)
	require.ErrorIs(t, err, ErrAuthArtifactMissing)
	id = strings.Repeat("d", 64)
	require.NoError(t, StoreAuthArtifact(PendingSecondFactor, id, []byte(PendingTokenValue("pending-user", gen)), "pending-user", gen, time.Minute))
	_, err = BumpAuthGeneration("pending-user")
	require.NoError(t, err)
	data, err := GetAuthArtifact(PendingSecondFactor, id)
	require.Error(t, err)
	assert.Nil(t, data)
}
