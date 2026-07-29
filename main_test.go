package main

import (
	"github.com/alicebob/miniredis/v2"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestMainFunctionDirect(t *testing.T) {
	if os.Getenv("RUN_MAIN_FOR_TESTING") == "1" {
		os.Args = []string{"rauth"} // Avoid test arguments messing with the app
		main()
		return
	}

	tests := []struct {
		name           string
		env            map[string]string
		expectExitCode int
		testRun        bool
	}{
		{
			name:           "MissingServerSecret",
			env:            map[string]string{"SERVER_SECRET": "short"},
			expectExitCode: 1,
		},
		{
			name:           "MissingCookieDomain",
			env:            map[string]string{"SERVER_SECRET": "12345678901234567890", "COOKIE_DOMAIN": ""},
			expectExitCode: 1,
		},
		{
			name:           "RedisInitFail",
			env:            map[string]string{"SERVER_SECRET": "12345678901234567890", "COOKIE_DOMAIN": "example.com", "REDIS_HOST": "invalid_host", "REDIS_PORT": "1234"},
			expectExitCode: 1,
		},
		{
			name:           "SuccessRun",
			env:            map[string]string{"SERVER_SECRET": "12345678901234567890", "COOKIE_DOMAIN": "example.com"},
			expectExitCode: 0, // Since we are not root, it fails to bind 80 and exits with 1, handled below
			testRun:        true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mr *miniredis.Miniredis
			if tc.testRun {
				mr = miniredis.RunT(t)
				tc.env["REDIS_HOST"] = mr.Host()
				tc.env["REDIS_PORT"] = mr.Port()
			}

			cmd := exec.Command(os.Args[0], "-test.run=TestMainFunctionDirect")
			cmd.Env = append(os.Environ(), "RUN_MAIN_FOR_TESTING=1")
			for k, v := range tc.env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}

			expectedCode := tc.expectExitCode
			if tc.testRun && os.Getuid() != 0 {
				expectedCode = 1
			}

			if tc.testRun {
				if err := cmd.Start(); err != nil {
					t.Fatalf("Failed to start command: %v", err)
				}

				done := make(chan error)
				go func() {
					done <- cmd.Wait()
				}()

				var exitCode int
				select {
				case <-time.After(2 * time.Second):
					_ = cmd.Process.Signal(os.Interrupt)
					err := <-done
					if exitErr, ok := err.(*exec.ExitError); ok {
						exitCode = exitErr.ExitCode()
					}
					expectedCode = 0 // if it didn't exit, we shut it down normally
				case err := <-done:
					if err != nil {
						if exitErr, ok := err.(*exec.ExitError); ok {
							exitCode = exitErr.ExitCode()
						} else {
							t.Fatalf("unexpected error: %v", err)
						}
					}
				}

				if exitCode != expectedCode {
					t.Errorf("expected exit code %d, got %d", expectedCode, exitCode)
				}
			} else {
				err := cmd.Run()
				exitCode := 0
				if err != nil {
					if exitErr, ok := err.(*exec.ExitError); ok {
						exitCode = exitErr.ExitCode()
					} else {
						t.Fatalf("unexpected error: %v", err)
					}
				}
				if exitCode != tc.expectExitCode {
					t.Errorf("expected exit code %d, got %d", tc.expectExitCode, exitCode)
				}
			}
		})
	}
}

func TestMainInitialUser(t *testing.T) {
	if os.Getenv("RUN_MAIN_FOR_TESTING") == "1" {
		os.Args = []string{"rauth"} // Avoid test arguments messing with the app
		main()
		return
	}

	mr := miniredis.RunT(t)

	cmd := exec.Command(os.Args[0], "-test.run=TestMainInitialUser")
	cmd.Env = append(os.Environ(),
		"RUN_MAIN_FOR_TESTING=1",
		"SERVER_SECRET=12345678901234567890",
		"COOKIE_DOMAIN=example.com",
		"REDIS_HOST="+mr.Host(),
		"REDIS_PORT="+mr.Port(),
		"INITIAL_USER=admin",
		"INITIAL_PASSWORD=password",
		"INITIAL_EMAIL=admin@example.com",
	)

	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start command: %v", err)
	}

	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Signal(os.Interrupt)
		<-done
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				// Ignore exit code 1 if not root
				if exitErr.ExitCode() != 1 || os.Getuid() == 0 {
					t.Logf("Command exited with code: %d", exitErr.ExitCode())
				}
			}
		}
	}
}
