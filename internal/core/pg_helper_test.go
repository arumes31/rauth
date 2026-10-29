package core

import (
	"testing"

	"rauth/internal/pgtest"
)

// setupPG points PG at this package's empty test schema.
func setupPG(t testing.TB) {
	t.Helper()
	PG = pgtest.Open(t, Migrate)
	pgtest.Reset(t, PG)
}

// currentGen returns the user's auth generation, for calls that need the
// generation a request was authorized under.
func currentGen(t testing.TB, username string) string {
	t.Helper()
	gen, err := AuthGeneration(username)
	if err != nil {
		t.Fatal(err)
	}
	return gen
}
