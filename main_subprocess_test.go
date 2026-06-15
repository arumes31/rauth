package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
)

func TestMain_Subprocess(t *testing.T) {
	if os.Getenv("BE_MAIN") == "1" {
		main()
		return
	}

	tests := []struct {
		name       string
		env        map[string]string
		wantExit   int
		wantOutput string
		successRun bool
	}{
		{
			name: "missing server secret",
			env: map[string]string{
				"SERVER_SECRET": "",
			},
			wantExit:   1,
			wantOutput: "SERVER_SECRET must be set",
		},
		{
			name: "missing cookie domain",
			env: map[string]string{
				"SERVER_SECRET": "0123456789abcdef0123456789abcdef",
				"COOKIE_DOMAIN": "",
			},
			wantExit:   1,
			wantOutput: "COOKIE_DOMAIN must contain at least one domain",
		},
		{
			name: "redis init failed",
			env: map[string]string{
				"SERVER_SECRET": "0123456789abcdef0123456789abcdef",
				"COOKIE_DOMAIN": "example.com",
				"REDIS_HOST": "invalid-host",
				"REDIS_PORT": "1234",
			},
			wantExit:   1,
			wantOutput: "Redis initialization failed",
		},
		{
			name: "success starts server",
			env: map[string]string{
				"SERVER_SECRET": "0123456789abcdef0123456789abcdef",
				"COOKIE_DOMAIN": "example.com",
			},
			successRun: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := miniredis.RunT(t)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestMain_Subprocess")
			cmd.Env = append(os.Environ(), "BE_MAIN=1")
			for k, v := range tt.env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}

			if tt.successRun {
				cmd.Env = append(cmd.Env, "REDIS_HOST="+s.Host(), "REDIS_PORT="+s.Port())
			}

			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out

			err := cmd.Run()

			if tt.successRun {
				// We expect it to be killed by context timeout if it binds successfully,
				// or it might fail binding :80 and exit immediately. Either way, no hanging.
				if err != nil {
					if err.Error() == "signal: killed" || err.Error() == "context deadline exceeded" {
						// Expected behavior for long running server
					} else {
						// Expected behavior if binding to port 80 fails (runs as non-root usually)
						assert.Contains(t, out.String(), "shutting down the server")
					}
				}
			} else {
				if tt.wantExit != 0 {
					assert.Error(t, err)
					assert.Contains(t, out.String(), tt.wantOutput)
				}
			}
		})
	}
}
