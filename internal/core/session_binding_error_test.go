package core

import (
	"context"
	"errors"
	"rauth/internal/authstate"
	"testing"

	"github.com/stretchr/testify/require"
)

type countryWriteFailureStore struct {
	authstate.SessionStore
	changed bool
	err     error
}

func (s countryWriteFailureStore) UpdateCountry(context.Context, string, string) (bool, error) {
	return s.changed, s.err
}

func TestSessionGeoAuthorizationDistinguishesPersistenceFailure(t *testing.T) {
	sqlSecurityFixture(t)
	previous := securitySessions
	t.Cleanup(func() { securitySessions = previous })
	failure := errors.New("authority link unavailable")
	for _, tc := range []struct {
		changed bool
		err     error
	}{{false, failure}, {false, nil}, {true, nil}} {
		securitySessions = countryWriteFailureStore{changed: tc.changed, err: tc.err}
		valid, err := sessionGeoAuthorization(context.Background(), &Config{GeoChangeMode: "lenient"}, "synthetic", "unused", map[string]string{"country": "AT", "username": "synthetic"}, "192.0.2.1", "DE")
		require.Equal(t, tc.changed && tc.err == nil, valid)
		if tc.err != nil {
			require.ErrorIs(t, err, failure)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestUserIsAdminContextHonorsCancellation(t *testing.T) {
	sqlSecurityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	valid, err := UserIsAdminContext(ctx, "synthetic")
	require.False(t, valid)
	require.ErrorIs(t, err, context.Canceled)
}
