package main

import (
	"errors"
	"rauth/internal/clusterconfig"
	"rauth/internal/eventstore"
	"testing"
)

func TestFailureClassesNeverExposeWrappedConnectionDetails(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{{clusterconfig.ErrMount, "host_mount"}, {clusterconfig.ErrPrivateFile, "private_file"}, {clusterconfig.ErrInvalid, "configuration"}, {eventstore.ErrUnavailable, "database_unavailable"}, {errors.New("postgres://private:password@database/secret"), "operation_failed"}} {
		if got := failureClass(tc.err); got != tc.want {
			t.Fatalf("unexpected class %q", got)
		}
	}
}
