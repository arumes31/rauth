package core

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsureUserUIDs(t *testing.T) {
	setupPG(t)

	// A legacy user without UID and a modern one with a UID.
	require.NoError(t, PutUser(User{Username: "legacyuser", Email: "legacy@test.com"}))
	modernUID := "8d7f2a3e-1b4c-4d5e-9f60-7a8b9c0d1e2f"
	require.NoError(t, PutUser(User{Username: "modernuser", UID: modernUID}))

	EnsureUserUIDs()

	legacy, err := GetUser("legacyuser")
	require.NoError(t, err)
	require.NotEmpty(t, legacy.UID)
	name, err := GetUsernameByUID(legacy.UID)
	require.NoError(t, err)
	require.Equal(t, "legacyuser", name)

	modern, err := GetUser("modernuser")
	require.NoError(t, err)
	require.Equal(t, modernUID, modern.UID)
}
