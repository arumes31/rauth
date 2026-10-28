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
