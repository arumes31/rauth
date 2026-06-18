package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
)

func TestMain_SubprocessCoverage(t *testing.T) {
	if os.Getenv("BE_MAIN") == "1" {
		scenario := os.Getenv("SCENARIO")
		if scenario == "MainExit_PortBusy" {
			s := miniredis.RunT(t)
			os.Setenv("REDIS_HOST", s.Host())
			os.Setenv("REDIS_PORT", s.Port())

			go func() {
				main()
			}()
			time.Sleep(500 * time.Millisecond)

			p, err := os.FindProcess(os.Getpid())
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to find process: %v\n", err)
				os.Exit(1)
			}
			err = p.Signal(syscall.SIGTERM)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to send signal: %v\n", err)
				os.Exit(1)
			}
			time.Sleep(2 * time.Second)
			os.Exit(0)
		} else if scenario == "MainExit" {
            // we use this one to ensure main starts and exits fine when port is busy
            s := miniredis.RunT(t)
			os.Setenv("REDIS_HOST", s.Host())
			os.Setenv("REDIS_PORT", s.Port())
            main()
            return
        } else {
			main()
		}
		return
	}

	tests := []struct {
		name       string
		scenario   string
		envs       map[string]string
		expectExit int
	}{
		{
			name:       "MissingSecret",
			scenario:   "MissingSecret",
			envs:       map[string]string{"SERVER_SECRET": "short"},
			expectExit: 1,
		},
		{
			name:     "MissingCookieDomain",
			scenario: "MissingCookieDomain",
			envs: map[string]string{
				"SERVER_SECRET": "0123456789abcdef0123456789abcdef",
				"COOKIE_DOMAIN": "",
			},
			expectExit: 1,
		},
		{
			name:     "RedisInitFailure",
			scenario: "RedisInitFailure",
			envs: map[string]string{
				"SERVER_SECRET": "0123456789abcdef0123456789abcdef",
				"COOKIE_DOMAIN": "example.com",
				"REDIS_HOST":    "invalid-host-that-fails",
			},
			expectExit: 1,
		},
		{
			name:     "MainExit_PortBusy",
			scenario: "MainExit",
			envs: map[string]string{
				"SERVER_SECRET": "0123456789abcdef0123456789abcdef",
				"COOKIE_DOMAIN": "example.com",
			},
			expectExit: 1, // e.Start() will fail on port 80 since non-root process.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestMain_SubprocessCoverage")
			cmd.Env = os.Environ()
			cmd.Env = append(cmd.Env, "BE_MAIN=1", fmt.Sprintf("SCENARIO=%s", tt.scenario))
			for k, v := range tt.envs {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
			}

			out, err := cmd.CombinedOutput()
			if tt.expectExit != 0 {
				if e, ok := err.(*exec.ExitError); ok {
					assert.Equal(t, tt.expectExit, e.ExitCode())
				} else {
					t.Fatalf("expected exit code %d, got err %v\nOutput: %s", tt.expectExit, err, string(out))
				}
			} else {
				if err != nil {
					t.Fatalf("expected success, got err %v\nOutput: %s", err, string(out))
				}
			}
		})
	}
}
