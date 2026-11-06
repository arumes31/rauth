package clusterpool

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCloseBoundedWithoutPoolsReturnsImmediately(t *testing.T) {
	started := time.Now()
	if !CloseBounded(time.Second) {
		t.Fatal("no pools must count as closed")
	}
	if !CloseBounded(time.Second, nil, (*pgxpool.Pool)(nil)) {
		t.Fatal("nil pools must count as closed")
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("returned after %v", elapsed)
	}
}
