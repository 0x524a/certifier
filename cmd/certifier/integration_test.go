package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var certifierBinary string

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "certifier-integration")
	if err != nil {
		panic(err)
	}

	certifierBinary = filepath.Join(tmpDir, "certifier")
	build := exec.Command("go", "build", "-o", certifierBinary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		_ = os.RemoveAll(tmpDir)
		panic("failed to build certifier binary: " + err.Error() + "\n" + string(out))
	}

	// os.Exit skips deferred calls, so cleanup must happen before calling it
	// rather than via defer.
	code := m.Run()
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}

// runResult captures the outcome of running the certifier binary.
type runResult struct {
	stdout   string
	stderr   string
	exitCode int
}

// run executes the certifier binary with the given args in dir and returns the result.
func run(t *testing.T, dir string, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(certifierBinary, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run certifier %v: %v", args, err)
		}
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: exitCode}
}

// runWithTimeout executes the certifier binary with a bounded context and empty stdin,
// used for cases that would otherwise fall into an interactive prompt loop.
func runWithTimeout(t *testing.T, dir string, timeout time.Duration, args ...string) runResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, certifierBinary, args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader("")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("certifier %v timed out after %s (likely hung waiting on stdin)", args, timeout)
	}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run certifier %v: %v", args, err)
		}
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: exitCode}
}

func requireFileExists(t *testing.T, dir, name string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Errorf("expected file %s to exist: %v", name, err)
	}
}

func TestTopLevelCommands(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name       string
		args       []string
		wantExit   int
		wantStdout string
		wantStderr string
	}{
		{name: "help", args: []string{"help"}, wantExit: 0, wantStderr: "certifier - X.509 Certificate Management Tool"},
		{name: "-h", args: []string{"-h"}, wantExit: 0, wantStderr: "certifier - X.509 Certificate Management Tool"},
		{name: "--help", args: []string{"--help"}, wantExit: 0, wantStderr: "certifier - X.509 Certificate Management Tool"},
		{name: "version", args: []string{"version"}, wantExit: 0, wantStdout: "certifier version 1.0.0"},
		{name: "-v", args: []string{"-v"}, wantExit: 0, wantStdout: "certifier version 1.0.0"},
		{name: "--version", args: []string{"--version"}, wantExit: 0, wantStdout: "certifier version 1.0.0"},
		{name: "unknown command", args: []string{"bogus-command"}, wantExit: 1, wantStderr: "Unknown command: bogus-command"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := run(t, dir, tt.args...)
			if res.exitCode != tt.wantExit {
				t.Errorf("exit code = %d, want %d (stdout=%q stderr=%q)", res.exitCode, tt.wantExit, res.stdout, res.stderr)
			}
			if tt.wantStdout != "" && !strings.Contains(res.stdout, tt.wantStdout) {
				t.Errorf("stdout = %q, want to contain %q", res.stdout, tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(res.stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want to contain %q", res.stderr, tt.wantStderr)
			}
			if tt.name == "unknown command" && !strings.Contains(res.stderr, "certifier - X.509 Certificate Management Tool") {
				t.Errorf("expected usage text in stderr for unknown command, got %q", res.stderr)
			}
		})
	}
}

func TestCAInteractiveNoHang(t *testing.T) {
	dir := t.TempDir()
	// "ca" with no subcommand and no flags defaults to interactive generate mode.
	// With empty stdin this must fail fast (missing CN) rather than hang.
	res := runWithTimeout(t, dir, 5*time.Second, "ca")
	if res.exitCode == 0 {
		t.Errorf("expected non-zero exit for interactive ca generate with empty stdin, got 0 (stdout=%q stderr=%q)", res.stdout, res.stderr)
	}
}

func TestCASubcommands(t *testing.T) {
	dir := t.TempDir()

	t.Run("generate missing cn", func(t *testing.T) {
		res := run(t, dir, "ca", "generate", "--non-interactive")
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1 (stderr=%q)", res.exitCode, res.stderr)
		}
		if !strings.Contains(res.stderr, "Common Name") && !strings.Contains(strings.ToLower(res.stderr), "common name") {
			t.Errorf("stderr = %q, want mention of required CN", res.stderr)
		}
	})

	t.Run("generate success", func(t *testing.T) {
		res := run(t, dir, "ca", "generate", "--cn", "Test CA", "--non-interactive", "--output", "ca.crt", "--key-output", "ca.key")
		if res.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		requireFileExists(t, dir, "ca.crt")
		requireFileExists(t, dir, "ca.key")
	})

	t.Run("view success", func(t *testing.T) {
		res := run(t, dir, "ca", "view", "--cert", "ca.crt")
		if res.exitCode != 0 {
			t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("view nonexistent", func(t *testing.T) {
		res := run(t, dir, "ca", "view", "--cert", "/nonexistent")
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1 (stderr=%q)", res.exitCode, res.stderr)
		}
	})

	t.Run("bogus subcommand", func(t *testing.T) {
		res := run(t, dir, "ca", "bogus-subcommand")
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1 (stderr=%q)", res.exitCode, res.stderr)
		}
		if !strings.Contains(res.stderr, "Unknown ca subcommand") {
			t.Errorf("stderr = %q, want to contain %q", res.stderr, "Unknown ca subcommand")
		}
	})
}

// TestFullWorkflow exercises cert/csr/crl/ocsp subcommands in dependency order
// within a single shared temp dir: CA -> cert -> csr -> sign -> validate -> crl -> ocsp.
func TestFullWorkflow(t *testing.T) {
	dir := t.TempDir()

	t.Run("ca generate", func(t *testing.T) {
		res := run(t, dir, "ca", "generate", "--cn", "Test CA", "--non-interactive", "--output", "ca.crt", "--key-output", "ca.key")
		if res.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		requireFileExists(t, dir, "ca.crt")
		requireFileExists(t, dir, "ca.key")
	})

	t.Run("cert generate", func(t *testing.T) {
		res := run(t, dir, "cert", "generate", "--cn", "example.com", "--non-interactive", "--output", "server.crt", "--key-output", "server.key")
		if res.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		requireFileExists(t, dir, "server.crt")
		requireFileExists(t, dir, "server.key")
	})

	t.Run("cert view", func(t *testing.T) {
		res := run(t, dir, "cert", "view", "--cert", "server.crt")
		if res.exitCode != 0 {
			t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("cert bogus subcommand", func(t *testing.T) {
		res := run(t, dir, "cert", "bogus-subcommand")
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1 (stderr=%q)", res.exitCode, res.stderr)
		}
	})

	t.Run("csr generate", func(t *testing.T) {
		res := run(t, dir, "csr", "generate", "--cn", "example.com", "--dns", "example.com", "--non-interactive", "--output", "test.csr", "--key-output", "test.key")
		if res.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		requireFileExists(t, dir, "test.csr")
		requireFileExists(t, dir, "test.key")
	})

	t.Run("csr view", func(t *testing.T) {
		res := run(t, dir, "csr", "view", "--csr", "test.csr")
		if res.exitCode != 0 {
			t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("cert sign", func(t *testing.T) {
		res := run(t, dir, "cert", "sign", "--csr", "test.csr", "--ca-cert", "ca.crt", "--ca-key", "ca.key", "--output", "signed.crt")
		if res.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		requireFileExists(t, dir, "signed.crt")
	})

	t.Run("cert validate", func(t *testing.T) {
		res := run(t, dir, "cert", "validate", "--cert", "signed.crt", "--roots", "ca.crt")
		if res.exitCode != 0 {
			t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("top-level validate routes to cert validate", func(t *testing.T) {
		res := run(t, dir, "validate", "--cert", "signed.crt", "--roots", "ca.crt")
		if res.exitCode != 0 {
			t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("top-level view routes to cert view", func(t *testing.T) {
		res := run(t, dir, "view", "--cert", "server.crt")
		if res.exitCode != 0 {
			t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("encode to der", func(t *testing.T) {
		res := run(t, dir, "encode", "--input", "server.crt", "--output", "server.der", "--format", "der")
		if res.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		requireFileExists(t, dir, "server.der")
	})

	t.Run("decode from der", func(t *testing.T) {
		res := run(t, dir, "decode", "--input", "server.der", "--output", "roundtrip.crt", "--format", "der")
		if res.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		requireFileExists(t, dir, "roundtrip.crt")
	})

	t.Run("csr bogus subcommand", func(t *testing.T) {
		res := run(t, dir, "csr", "bogus-subcommand")
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1 (stderr=%q)", res.exitCode, res.stderr)
		}
	})

	t.Run("crl generate", func(t *testing.T) {
		res := run(t, dir, "crl", "generate", "--ca-cert", "ca.crt", "--ca-key", "ca.key", "--output", "test.crl", "--revoked", "1,2,3")
		if res.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		requireFileExists(t, dir, "test.crl")
	})

	t.Run("crl view", func(t *testing.T) {
		res := run(t, dir, "crl", "view", "--crl", "test.crl")
		if res.exitCode != 0 {
			t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
	})

	t.Run("crl check not revoked", func(t *testing.T) {
		res := run(t, dir, "crl", "check", "--crl", "test.crl", "--cert", "server.crt")
		if res.exitCode != 0 {
			t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "NOT revoked") {
			t.Errorf("stdout = %q, want to contain %q", res.stdout, "NOT revoked")
		}
	})

	t.Run("crl no subcommand", func(t *testing.T) {
		res := run(t, dir, "crl")
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1 (stderr=%q)", res.exitCode, res.stderr)
		}
		if !strings.Contains(res.stderr, "Usage: certifier crl") {
			t.Errorf("stderr = %q, want usage message", res.stderr)
		}
	})

	t.Run("crl bogus subcommand", func(t *testing.T) {
		res := run(t, dir, "crl", "bogus")
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1 (stderr=%q)", res.exitCode, res.stderr)
		}
		if !strings.Contains(res.stderr, "Unknown crl subcommand") {
			t.Errorf("stderr = %q, want to contain %q", res.stderr, "Unknown crl subcommand")
		}
	})

	for _, helpFlag := range []string{"-h", "--help"} {
		t.Run("crl "+helpFlag, func(t *testing.T) {
			res := run(t, dir, "crl", helpFlag)
			if res.exitCode != 0 {
				t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
			}
			if !strings.Contains(res.stdout, "Usage: certifier crl") {
				t.Errorf("stdout = %q, want usage message", res.stdout)
			}
		})
	}

	t.Run("ocsp request", func(t *testing.T) {
		res := run(t, dir, "ocsp", "request", "--cert", "server.crt", "--ca-cert", "ca.crt", "--output", "req.der")
		if res.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		requireFileExists(t, dir, "req.der")
	})

	t.Run("ocsp response", func(t *testing.T) {
		res := run(t, dir, "ocsp", "response", "--cert", "server.crt", "--ca-cert", "ca.crt", "--responder-key", "ca.key", "--status", "good", "--output", "resp.der")
		if res.exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		requireFileExists(t, dir, "resp.der")
	})

	t.Run("ocsp verify", func(t *testing.T) {
		res := run(t, dir, "ocsp", "verify", "--response", "resp.der", "--cert", "server.crt", "--ca-cert", "ca.crt")
		if res.exitCode != 0 {
			t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "Verified: true") {
			t.Errorf("stdout = %q, want to contain %q", res.stdout, "Verified: true")
		}
	})

	t.Run("ocsp check without url or AIA entry", func(t *testing.T) {
		// server.crt has no OCSP AIA entry, and no --url is given, so this
		// must fail fast with a clear error rather than hang on network I/O.
		res := run(t, dir, "ocsp", "check", "--cert", "server.crt", "--ca-cert", "ca.crt")
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, "OCSP URL is required") {
			t.Errorf("stderr = %q, want to contain %q", res.stderr, "OCSP URL is required")
		}
	})

	t.Run("ocsp no subcommand", func(t *testing.T) {
		res := run(t, dir, "ocsp")
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1 (stderr=%q)", res.exitCode, res.stderr)
		}
		if !strings.Contains(res.stderr, "Usage: certifier ocsp") {
			t.Errorf("stderr = %q, want usage message", res.stderr)
		}
	})

	t.Run("ocsp bogus subcommand", func(t *testing.T) {
		res := run(t, dir, "ocsp", "bogus")
		if res.exitCode != 1 {
			t.Errorf("exit code = %d, want 1 (stderr=%q)", res.exitCode, res.stderr)
		}
		if !strings.Contains(res.stderr, "Unknown ocsp subcommand") {
			t.Errorf("stderr = %q, want to contain %q", res.stderr, "Unknown ocsp subcommand")
		}
	})

	for _, helpFlag := range []string{"-h", "--help"} {
		t.Run("ocsp "+helpFlag, func(t *testing.T) {
			res := run(t, dir, "ocsp", helpFlag)
			if res.exitCode != 0 {
				t.Errorf("exit code = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
			}
			if !strings.Contains(res.stdout, "Usage: certifier ocsp") {
				t.Errorf("stdout = %q, want usage message", res.stdout)
			}
		})
	}
}
