# Migrate CLI dispatch/flag-parsing to urfave/cli v3 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-rolled `os.Args` switch in `cmd/certifier/main.go` and the per-command `flag.NewFlagSet` blocks in `internal/cli/*.go` with a `github.com/urfave/cli/v3` command tree, preserving all existing behavior exactly (error text, exit codes, flag defaults) while also polishing leaf-command `-h` output (real one-line `Usage` strings instead of urfave's generic placeholder).

**Architecture:** Every existing `XxxCmd(args []string) error` function keeps its exact signature (so the ~5000 lines of existing `internal/cli/*_test.go` tests need zero changes) but delegates to a new `xxxCommand() *cliv3.Command` constructor via a shared `runLeafCommand` helper. Group commands (`ca`, `cert`, `csr`, `crl`, `ocsp`) use `SkipFlagParsing: true` plus a manual `Action` that replicates today's `handleXxxCommand` dispatch logic exactly (verified against the real library via compiled probes, not guessed), while their registered sub-commands still auto-dispatch by name. `cli.RootCommand()` assembles everything; `cmd/certifier/main.go` shrinks to ~12 lines.

**Tech Stack:** Go, `github.com/urfave/cli/v3` v3.11.0.

**Spec:** `docs/superpowers/specs/2026-09-13-urfave-cli-migration-design.md`

## Global Constraints

- Preserve exact behavior (error text, exit codes, flag names/defaults/required-ness) for every existing command — this is a plumbing-only migration, not a behavior change, except where explicitly called out below.
- Deliberate, accepted improvements (not regressions, not gated on tests since none assert the old broken behavior): every leaf command now supports working `-h`/`--help` (exit 0, real generated help) where before it often errored (exit 1) or was simply unhandled.
- Polish: every leaf `*cliv3.Command` gets a real one-line `Usage` field (shown in its own `-h` output) instead of urfave's default empty/placeholder text. Group commands (`ca`, `cert`, etc.) use `SkipFlagParsing` and a manual `Action`, so their own `Usage` field is never rendered — do not bother setting it.
- No changes to certificate/CSR/CRL/OCSP/encoding/validation business logic (`pkg/*`) or to the interactive menu/prompt system (`internal/cli/menu.go`, `internal/cli/interactive.go`) — only the flag-parsing/dispatch plumbing around them changes.
- Every business-logic error message and every "Unknown X subcommand" / usage-line string is preserved character-for-character from the current source.
- After every task: `go build ./...` and `go test ./...` must pass before moving to the next task.

---

## Task 1: Add urfave/cli/v3 dependency and shared support code

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `internal/cli/cli_support.go`
- Create: `internal/cli/cli_support_test.go`

**Interfaces:**
- Produces: `runLeafCommand(cmd *cliv3.Command, args []string) error`, `isFlag(s string) bool`, `var ErrSilent error` — used by every later task.

- [ ] **Step 1: Add the dependency**

Run:
```bash
go get github.com/urfave/cli/v3@v3.11.0
go mod tidy
```
Expected: `go.mod` gains a `require github.com/urfave/cli/v3 v3.11.0` line; `go build ./...` still succeeds (nothing imports it yet).

- [ ] **Step 2: Write the failing test for `runLeafCommand`**

Create `internal/cli/cli_support_test.go`:

```go
package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	cliv3 "github.com/urfave/cli/v3"
)

func TestRunLeafCommandWrapsFlagParseErrors(t *testing.T) {
	cmd := &cliv3.Command{
		Name:  "test",
		Flags: []cliv3.Flag{&cliv3.StringFlag{Name: "cn"}},
		Action: func(ctx context.Context, c *cliv3.Command) error {
			return nil
		},
	}

	err := runLeafCommand(cmd, []string{"--bogus", "x"})
	if err == nil {
		t.Fatal("expected an error for an undefined flag")
	}
	if !strings.HasPrefix(err.Error(), "error parsing flags: ") {
		t.Errorf("error = %q, want prefix %q", err.Error(), "error parsing flags: ")
	}
}

func TestRunLeafCommandPassesThroughActionErrors(t *testing.T) {
	wantErr := errors.New("common Name (--cn) is required for non-interactive mode")
	cmd := &cliv3.Command{
		Name:  "test",
		Flags: []cliv3.Flag{&cliv3.StringFlag{Name: "cn"}},
		Action: func(ctx context.Context, c *cliv3.Command) error {
			return wantErr
		},
	}

	err := runLeafCommand(cmd, nil)
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want %v", err, wantErr)
	}
}

func TestRunLeafCommandSuccessBindsDestination(t *testing.T) {
	var gotCN string
	cmd := &cliv3.Command{
		Name:  "test",
		Flags: []cliv3.Flag{&cliv3.StringFlag{Name: "cn", Destination: &gotCN}},
		Action: func(ctx context.Context, c *cliv3.Command) error {
			return nil
		},
	}

	if err := runLeafCommand(cmd, []string{"--cn", "hello"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotCN != "hello" {
		t.Errorf("cn = %q, want %q", gotCN, "hello")
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestRunLeafCommand -v`
Expected: FAIL — `runLeafCommand` is undefined (compile error).

- [ ] **Step 4: Implement `runLeafCommand`, `isFlag`, and `ErrSilent`**

Create `internal/cli/cli_support.go`:

```go
package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cliv3 "github.com/urfave/cli/v3"
)

// ErrSilent signals that the error's message has already been printed to
// stderr by the code that produced it (e.g. an "Unknown X subcommand"
// line), so the top-level caller in cmd/certifier/main.go should set a
// non-zero exit code without printing anything further.
var ErrSilent = errors.New("silent")

// isFlag reports whether s looks like a command-line flag.
func isFlag(s string) bool {
	return strings.HasPrefix(s, "-")
}

// runLeafCommand runs cmd against args, translating urfave/cli's own
// flag-parsing errors into the "error parsing flags: %w" shape the
// existing *Cmd functions and their tests expect, while passing through
// any error returned by cmd's own Action unwrapped (so business-logic
// error messages like "CA certificate is required" reach callers exactly
// as before).
func runLeafCommand(cmd *cliv3.Command, args []string) error {
	ranAction := false
	action := cmd.Action
	cmd.Action = func(ctx context.Context, c *cliv3.Command) error {
		ranAction = true
		return action(ctx, c)
	}
	cmd.OnUsageError = func(ctx context.Context, c *cliv3.Command, err error, isSubcommand bool) error {
		return err
	}

	err := cmd.Run(context.Background(), append([]string{cmd.Name}, args...))
	if err != nil && !ranAction {
		return fmt.Errorf("error parsing flags: %w", err)
	}
	return err
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/cli/... -run TestRunLeafCommand -v`
Expected: PASS (all 3 tests).

- [ ] **Step 6: Full package build/test check**

Run: `go build ./... && go test ./...`
Expected: PASS, no regressions (nothing else uses the new code yet).

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/cli/cli_support.go internal/cli/cli_support_test.go
git commit -m "Add urfave/cli/v3 dependency and shared leaf-command runner"
```

---

## Task 2: Migrate the `ca` group (`internal/cli/commands.go`)

**Files:**
- Modify: `internal/cli/commands.go`
- Create: `internal/cli/ca_group_test.go`

**Interfaces:**
- Consumes: `runLeafCommand`, `isFlag`, `ErrSilent` from Task 1.
- Produces: `caGenerateCommand() *cliv3.Command`, `caViewCommand() *cliv3.Command`, `caCommand() *cliv3.Command` — `caCommand()` is consumed by Task 10 (root.go).

- [ ] **Step 1: Write the failing tests for the new group-dispatch behavior**

Create `internal/cli/ca_group_test.go`:

```go
package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCACommandUnknownSubcommand(t *testing.T) {
	err := caCommand().Run(context.Background(), []string{"ca", "bogus-subcommand"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestCACommandFlagFirstArgDefaultsToGenerate(t *testing.T) {
	dir := t.TempDir()
	certOut := filepath.Join(dir, "ca.crt")
	keyOut := filepath.Join(dir, "ca.key")

	err := caCommand().Run(context.Background(), []string{
		"ca", "--cn", "Test CA", "--non-interactive",
		"--output", certOut, "--key-output", keyOut,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(certOut); statErr != nil {
		t.Errorf("expected cert file to exist: %v", statErr)
	}
}

func TestCACommandGenerateSubcommand(t *testing.T) {
	dir := t.TempDir()
	certOut := filepath.Join(dir, "ca.crt")
	keyOut := filepath.Join(dir, "ca.key")

	err := caCommand().Run(context.Background(), []string{
		"ca", "generate", "--cn", "Test CA", "--non-interactive",
		"--output", certOut, "--key-output", keyOut,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(certOut); statErr != nil {
		t.Errorf("expected cert file to exist: %v", statErr)
	}
}

func TestCACommandViewSubcommand(t *testing.T) {
	dir := t.TempDir()
	certOut := filepath.Join(dir, "ca.crt")
	keyOut := filepath.Join(dir, "ca.key")
	if err := caCommand().Run(context.Background(), []string{
		"ca", "generate", "--cn", "Test CA", "--non-interactive",
		"--output", certOut, "--key-output", keyOut,
	}); err != nil {
		t.Fatalf("setup: unexpected error: %v", err)
	}

	if err := caCommand().Run(context.Background(), []string{"ca", "view", "--cert", certOut}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestCACommand -v`
Expected: FAIL — `caCommand` is undefined (compile error).

- [ ] **Step 3: Replace `GenerateCACmd`'s body and add the constructors**

In `internal/cli/commands.go`, add to the import block:

```go
	"context"

	cliv3 "github.com/urfave/cli/v3"
```

(Leave the existing `"flag"` import in place for now — `GenerateCertCmd`, `ViewCertCmd`, and `GenerateCSRCmd` still use it until Tasks 3 and 5.)

Replace the entire `GenerateCACmd` function (lines 17-169 in the original) with:

```go
func caGenerateCommand() *cliv3.Command {
	var cn, country, org, orgUnit, locality, province, keyType, certOutput, keyOutput string
	var validityDays int
	var nonInteractive bool

	return &cliv3.Command{
		Name:  "generate",
		Usage: "Generate a CA certificate",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cn", Usage: "Common Name (required)", Destination: &cn},
			&cliv3.StringFlag{Name: "country", Value: "US", Usage: "Country", Destination: &country},
			&cliv3.StringFlag{Name: "org", Usage: "Organization", Destination: &org},
			&cliv3.StringFlag{Name: "ou", Usage: "Organizational Unit", Destination: &orgUnit},
			&cliv3.StringFlag{Name: "locality", Usage: "Locality", Destination: &locality},
			&cliv3.StringFlag{Name: "province", Usage: "Province/State", Destination: &province},
			&cliv3.IntFlag{Name: "validity", Value: 365 * 10, Usage: "Validity in days", Destination: &validityDays},
			&cliv3.StringFlag{Name: "key-type", Value: "rsa2048", Usage: "Key type (rsa2048, rsa4096, ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519)", Destination: &keyType},
			&cliv3.StringFlag{Name: "output", Value: "ca.crt", Usage: "Output certificate file", Destination: &certOutput},
			&cliv3.StringFlag{Name: "key-output", Value: "ca.key", Usage: "Output private key file", Destination: &keyOutput},
			&cliv3.BoolFlag{Name: "non-interactive", Usage: "Enable non-interactive mode (requires --cn)", Destination: &nonInteractive},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			useInteractive := !nonInteractive && cn == ""

			if useInteractive {
				im := NewInteractiveMode()
				fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
				fmt.Println("║            CA GENERATION - INTERACTIVE MODE                ║")
				fmt.Println("╚════════════════════════════════════════════════════════════╝")

				subject := im.PromptSubjectInfo()
				if subject["commonName"] == "" {
					return fmt.Errorf("common Name is required")
				}

				keyTypeStr := im.PromptKeyType()
				validity := im.PromptValidity()
				certOut := im.PromptFileOutput("ca.crt")
				keyOut := im.PromptFileOutput("ca.key")

				certConfig := &cert.CertificateConfig{
					CommonName:         subject["commonName"],
					Country:            subject["country"],
					Organization:       subject["organization"],
					OrganizationalUnit: subject["organizationalUnit"],
					Locality:           subject["locality"],
					Province:           subject["province"],
					KeyType:            cert.KeyType(keyTypeStr),
					Validity:           validity,
					IsCA:               true,
					MaxPathLength:      -1,
				}

				summary := map[string]interface{}{
					"Common Name":      certConfig.CommonName,
					"Organization":     certConfig.Organization,
					"Key Type":         string(certConfig.KeyType),
					"Validity":         fmt.Sprintf("%d days", certConfig.Validity),
					"Certificate Type": "CA",
				}
				SummaryTable(summary)

				if !im.ConfirmGeneration() {
					fmt.Println("CA generation cancelled.")
					return nil
				}

				certificate, privateKey, err := cert.GenerateSelfSignedCertificate(certConfig)
				if err != nil {
					return fmt.Errorf("error generating CA certificate: %w", err)
				}

				certPEM, err := encoding.EncodeCertificateToPEM(certificate)
				if err != nil {
					return fmt.Errorf("error encoding certificate: %w", err)
				}

				keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
				if err != nil {
					return fmt.Errorf("error encoding private key: %w", err)
				}

				if err := os.WriteFile(certOut, certPEM, 0644); err != nil {
					return fmt.Errorf("error writing certificate file: %w", err)
				}

				if err := os.WriteFile(keyOut, keyPEM, 0600); err != nil {
					return fmt.Errorf("error writing key file: %w", err)
				}

				fmt.Printf("CA Certificate generated successfully!\n")
				fmt.Printf("Certificate: %s\n", certOut)
				fmt.Printf("Private Key: %s\n", keyOut)
				fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
				fmt.Printf("Valid From: %s\n", certificate.NotBefore)
				fmt.Printf("Valid Until: %s\n", certificate.NotAfter)
				return nil
			}

			if cn == "" {
				return fmt.Errorf("common Name (--cn) is required for non-interactive mode")
			}

			certConfig := &cert.CertificateConfig{
				CommonName:         cn,
				Country:            country,
				Organization:       org,
				OrganizationalUnit: orgUnit,
				Locality:           locality,
				Province:           province,
				KeyType:            cert.KeyType(keyType),
				Validity:           validityDays,
				IsCA:               true,
				MaxPathLength:      -1,
			}

			certificate, privateKey, err := cert.GenerateSelfSignedCertificate(certConfig)
			if err != nil {
				return fmt.Errorf("error generating CA certificate: %w", err)
			}

			certPEM, err := encoding.EncodeCertificateToPEM(certificate)
			if err != nil {
				return fmt.Errorf("error encoding certificate: %w", err)
			}

			keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
			if err != nil {
				return fmt.Errorf("error encoding private key: %w", err)
			}

			if err := os.WriteFile(certOutput, certPEM, 0644); err != nil {
				return fmt.Errorf("error writing certificate file: %w", err)
			}

			if err := os.WriteFile(keyOutput, keyPEM, 0600); err != nil {
				return fmt.Errorf("error writing key file: %w", err)
			}

			fmt.Printf("CA Certificate generated successfully!\n")
			fmt.Printf("Certificate: %s\n", certOutput)
			fmt.Printf("Private Key: %s\n", keyOutput)
			fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
			fmt.Printf("Valid From: %s\n", certificate.NotBefore)
			fmt.Printf("Valid Until: %s\n", certificate.NotAfter)
			return nil
		},
	}
}

// GenerateCACmd generates a CA certificate and returns an error instead of exiting
func GenerateCACmd(args []string) error {
	return runLeafCommand(caGenerateCommand(), args)
}
```

Replace the entire `ViewCACmd` function (originally lines 594-607) with:

```go
func caViewCommand() *cliv3.Command {
	var certFile string
	return &cliv3.Command{
		Name:  "view",
		Usage: "View a CA certificate",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cert", Usage: "CA certificate file (required)", Destination: &certFile},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if certFile == "" {
				return fmt.Errorf("CA certificate file (--cert) is required")
			}
			return ViewCertificateDetailsCmd(certFile)
		},
	}
}

// ViewCACmd views CA details and returns an error instead of exiting
func ViewCACmd(args []string) error {
	return runLeafCommand(caViewCommand(), args)
}
```

Add the group constructor right after (new code, not a replacement):

```go
func caCommand() *cliv3.Command {
	return &cliv3.Command{
		Name:            "ca",
		Commands:        []*cliv3.Command{caGenerateCommand(), caViewCommand()},
		SkipFlagParsing: true,
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			args := cmd.Args().Slice()
			if len(args) == 0 || isFlag(args[0]) {
				return GenerateCACmd(args)
			}
			fmt.Fprintf(os.Stderr, "Unknown ca subcommand: %s\n", args[0])
			return ErrSilent
		},
	}
}
```

- [ ] **Step 4: Run the new tests and the full existing suite**

Run: `go test ./internal/cli/... -v`
Expected: PASS — the new `TestCACommand*` tests pass, and every pre-existing test in `commands_test.go` that calls `GenerateCACmd`/`ViewCACmd`/`GenerateCA`/`ViewCA` directly still passes unchanged (their signatures didn't change).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/commands.go internal/cli/ca_group_test.go
git commit -m "Migrate ca command group to urfave/cli v3"
```

---

## Task 3: Migrate `cert generate` and `cert view` (`internal/cli/commands.go`)

**Files:**
- Modify: `internal/cli/commands.go`

**Interfaces:**
- Consumes: `runLeafCommand`, `splitAndTrimCSV` (existing helper, unchanged), `GenerateCertFromFileCmd` (existing, unchanged).
- Produces: `certGenerateCommand() *cliv3.Command`, `certViewCommand() *cliv3.Command` — both consumed by Task 4 (`certCommand()` group) and Task 10 (`certViewCommand()` reused as the top-level `view` alias).

- [ ] **Step 1: Replace `GenerateCertCmd`'s body**

Replace the entire `GenerateCertCmd` function (originally lines 193-341) with:

```go
func certGenerateCommand() *cliv3.Command {
	var cn, country, org, orgUnit, locality, province, keyType, certType string
	var dnsNames, ipAddrs, extKeyUsageOIDs, ocspURLs string
	var caCertFile, caKeyFile, certOutput, keyOutput, configFile string
	var validityDays int
	var nonInteractive bool

	return &cliv3.Command{
		Name:  "generate",
		Usage: "Generate a certificate",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cn", Usage: "Common Name (required)", Destination: &cn},
			&cliv3.StringFlag{Name: "country", Value: "US", Usage: "Country", Destination: &country},
			&cliv3.StringFlag{Name: "org", Usage: "Organization", Destination: &org},
			&cliv3.StringFlag{Name: "ou", Usage: "Organizational Unit", Destination: &orgUnit},
			&cliv3.StringFlag{Name: "locality", Usage: "Locality", Destination: &locality},
			&cliv3.StringFlag{Name: "province", Usage: "Province/State", Destination: &province},
			&cliv3.IntFlag{Name: "validity", Value: 365, Usage: "Validity in days", Destination: &validityDays},
			&cliv3.StringFlag{Name: "key-type", Value: "rsa2048", Usage: "Key type", Destination: &keyType},
			&cliv3.StringFlag{Name: "cert-type", Value: "server", Usage: "Certificate type (client, server, or both)", Destination: &certType},
			&cliv3.StringFlag{Name: "dns", Usage: "DNS names (comma-separated)", Destination: &dnsNames},
			&cliv3.StringFlag{Name: "ip", Usage: "IP addresses (comma-separated)", Destination: &ipAddrs},
			&cliv3.StringFlag{Name: "ext-oid", Usage: "Extended key usage OIDs (comma-separated)", Destination: &extKeyUsageOIDs},
			&cliv3.StringFlag{Name: "ocsp-url", Usage: "OCSP responder URL(s) for the certificate's AIA extension (comma-separated)", Destination: &ocspURLs},
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (for signing)", Destination: &caCertFile},
			&cliv3.StringFlag{Name: "ca-key", Usage: "CA private key file (for signing)", Destination: &caKeyFile},
			&cliv3.StringFlag{Name: "output", Value: "cert.crt", Usage: "Output certificate file", Destination: &certOutput},
			&cliv3.StringFlag{Name: "key-output", Value: "cert.key", Usage: "Output private key file", Destination: &keyOutput},
			&cliv3.StringFlag{Name: "f", Usage: "Configuration file (YAML) for batch generation", Destination: &configFile},
			&cliv3.BoolFlag{Name: "non-interactive", Usage: "Enable non-interactive mode (requires --cn)", Destination: &nonInteractive},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if configFile != "" {
				return GenerateCertFromFileCmd(configFile)
			}

			if cn == "" && (nonInteractive || cn != "") {
				return fmt.Errorf("common Name (--cn) is required for non-interactive mode")
			}

			var dnsNamesList []string
			if dnsNames != "" {
				dnsNamesList = strings.Split(dnsNames, ",")
				for i, name := range dnsNamesList {
					dnsNamesList[i] = strings.TrimSpace(name)
				}
			}

			var ipAddrsList []net.IP
			if ipAddrs != "" {
				for _, addr := range strings.Split(ipAddrs, ",") {
					ip := net.ParseIP(strings.TrimSpace(addr))
					if ip != nil {
						ipAddrsList = append(ipAddrsList, ip)
					}
				}
			}

			var extOIDsList []string
			if extKeyUsageOIDs != "" {
				extOIDsList = strings.Split(extKeyUsageOIDs, ",")
				for i, oid := range extOIDsList {
					extOIDsList[i] = strings.TrimSpace(oid)
				}
			}

			ocspURLsList := splitAndTrimCSV(ocspURLs)

			var caCert *x509.Certificate
			var caPrivateKey interface{}

			if caCertFile != "" && caKeyFile != "" {
				caCertPEM, err := os.ReadFile(caCertFile)
				if err != nil {
					return fmt.Errorf("error reading CA certificate: %w", err)
				}

				caKeyPEM, err := os.ReadFile(caKeyFile)
				if err != nil {
					return fmt.Errorf("error reading CA key: %w", err)
				}

				caCert, err = encoding.DecodeCertificateFromPEM(caCertPEM)
				if err != nil {
					return fmt.Errorf("error parsing CA certificate: %w", err)
				}

				caPrivateKey, err = encoding.DecodePrivateKeyFromPEM(caKeyPEM)
				if err != nil {
					return fmt.Errorf("error parsing CA key: %w", err)
				}
			}

			config := &cert.CertificateConfig{
				CommonName:           cn,
				Country:              country,
				Organization:         org,
				OrganizationalUnit:   orgUnit,
				Locality:             locality,
				Province:             province,
				KeyType:              cert.KeyType(keyType),
				CertType:             cert.CertificateType(certType),
				Validity:             validityDays,
				DNSNames:             dnsNamesList,
				IPAddresses:          ipAddrsList,
				ExtendedKeyUsageOIDs: extOIDsList,
				OCSPServer:           ocspURLsList,
			}

			var certificate *x509.Certificate
			var privateKey interface{}
			var err error

			if caCert != nil && caPrivateKey != nil {
				certificate, privateKey, err = cert.GenerateCASignedCertificate(config, config, caPrivateKey, caCert)
			} else {
				certificate, privateKey, err = cert.GenerateSelfSignedCertificate(config)
			}

			if err != nil {
				return fmt.Errorf("error generating certificate: %w", err)
			}

			certPEM, err := encoding.EncodeCertificateToPEM(certificate)
			if err != nil {
				return fmt.Errorf("error encoding certificate: %w", err)
			}

			keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
			if err != nil {
				return fmt.Errorf("error encoding private key: %w", err)
			}

			if err := os.WriteFile(certOutput, certPEM, 0644); err != nil {
				return fmt.Errorf("error writing certificate file: %w", err)
			}

			if err := os.WriteFile(keyOutput, keyPEM, 0600); err != nil {
				return fmt.Errorf("error writing key file: %w", err)
			}

			fmt.Printf("Certificate generated successfully!\n")
			fmt.Printf("Certificate: %s\n", certOutput)
			fmt.Printf("Private Key: %s\n", keyOutput)
			if caCert != nil {
				fmt.Printf("Signed by CA\n")
			}
			fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
			fmt.Printf("Valid From: %s\n", certificate.NotBefore)
			fmt.Printf("Valid Until: %s\n", certificate.NotAfter)
			fmt.Printf("DNS Names: %s\n", strings.Join(config.DNSNames, ", "))

			return nil
		},
	}
}

// GenerateCertCmd generates a certificate and returns an error instead of exiting
func GenerateCertCmd(args []string) error {
	return runLeafCommand(certGenerateCommand(), args)
}
```

- [ ] **Step 2: Replace `ViewCertCmd`'s body**

Replace the entire `ViewCertCmd` function (originally lines 409-422) with:

```go
func certViewCommand() *cliv3.Command {
	var certFile string
	return &cliv3.Command{
		Name:  "view",
		Usage: "View certificate details",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate file (required)", Destination: &certFile},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}
			return ViewCertificateDetailsCmd(certFile)
		},
	}
}

// ViewCertCmd views certificate details and returns an error instead of exiting
func ViewCertCmd(args []string) error {
	return runLeafCommand(certViewCommand(), args)
}
```

- [ ] **Step 3: Run the full existing suite to confirm no regression**

Run: `go test ./internal/cli/... -v`
Expected: PASS — every pre-existing test calling `GenerateCertCmd`/`ViewCertCmd`/`GenerateCert`/`ViewCert` (including `TestGenerateCert`, `TestGenerateCertFromFile*`, `TestGenerateCertWithDNSNames`, `TestGenerateCertWithIPAddresses`, `TestGenerateCertWithExtendedValidity`, etc.) passes unchanged.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/commands.go
git commit -m "Migrate cert generate and cert view to urfave/cli v3"
```

---

## Task 4: Migrate `cert sign`, `cert validate`, and assemble the `cert` group (`internal/cli/misc_commands.go`)

**Files:**
- Modify: `internal/cli/misc_commands.go`
- Create: `internal/cli/cert_group_test.go`

**Interfaces:**
- Consumes: `certGenerateCommand()`, `certViewCommand()` (Task 3), `runLeafCommand`, `isFlag`, `ErrSilent` (Task 1), `loadCertificateFiles` (existing, unchanged).
- Produces: `certSignCommand() *cliv3.Command`, `certValidateCommand() *cliv3.Command`, `certCommand() *cliv3.Command` — `certValidateCommand()` also consumed by Task 10 (top-level `validate` alias).

- [ ] **Step 1: Write the failing tests for the group-dispatch behavior**

Create `internal/cli/cert_group_test.go`:

```go
package cli

import (
	"context"
	"errors"
	"testing"
)

func TestCertCommandUnknownSubcommand(t *testing.T) {
	err := certCommand().Run(context.Background(), []string{"cert", "bogus-subcommand"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestCertCommandFlagFirstArgDefaultsToGenerate(t *testing.T) {
	err := certCommand().Run(context.Background(), []string{"cert", "--non-interactive"})
	if err == nil || err.Error() != "common Name (--cn) is required for non-interactive mode" {
		t.Errorf("err = %v, want the missing-CN business error", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestCertCommand -v`
Expected: FAIL — `certCommand` is undefined (compile error).

- [ ] **Step 3: Replace `SignCertCmd`'s body**

In `internal/cli/misc_commands.go`, add to the import block:

```go
	"context"

	cliv3 "github.com/urfave/cli/v3"
```

(Leave `"flag"` in place — `ViewCSRCmd`, `EncodeCertCmd`, and `DecodeCertCmd` still use it until Tasks 6 and 7.)

Replace the entire `SignCertCmd` function (originally lines 16-88) with:

```go
func certSignCommand() *cliv3.Command {
	var csrFile, caCertFile, caKeyFile, output string
	var validityDays int

	return &cliv3.Command{
		Name:  "sign",
		Usage: "Sign a certificate with CA",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "csr", Usage: "CSR PEM file (required)", Destination: &csrFile},
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (required)", Destination: &caCertFile},
			&cliv3.StringFlag{Name: "ca-key", Usage: "CA private key file (required)", Destination: &caKeyFile},
			&cliv3.StringFlag{Name: "output", Value: "signed.crt", Usage: "Output certificate file", Destination: &output},
			&cliv3.IntFlag{Name: "validity", Value: 365, Usage: "Validity in days", Destination: &validityDays},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if csrFile == "" {
				return fmt.Errorf("CSR file (--csr) is required")
			}
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}
			if caKeyFile == "" {
				return fmt.Errorf("CA private key file (--ca-key) is required")
			}

			csrPEM, err := os.ReadFile(csrFile)
			if err != nil {
				return fmt.Errorf("error reading CSR file: %w", err)
			}

			csr, err := encoding.DecodeCSRFromPEM(csrPEM)
			if err != nil {
				return fmt.Errorf("error decoding CSR: %w", err)
			}

			caCertPEM, err := os.ReadFile(caCertFile)
			if err != nil {
				return fmt.Errorf("error reading CA certificate file: %w", err)
			}

			caCert, err := encoding.DecodeCertificateFromPEM(caCertPEM)
			if err != nil {
				return fmt.Errorf("error decoding CA certificate: %w", err)
			}

			caKeyPEM, err := os.ReadFile(caKeyFile)
			if err != nil {
				return fmt.Errorf("error reading CA private key file: %w", err)
			}

			caKey, err := encoding.DecodePrivateKeyFromPEM(caKeyPEM)
			if err != nil {
				return fmt.Errorf("error decoding CA private key: %w", err)
			}

			signedCert, err := cert.SignCSR(csr, caKey, caCert, validityDays)
			if err != nil {
				return fmt.Errorf("error signing CSR: %w", err)
			}

			signedPEM, err := encoding.EncodeCertificateToPEM(signedCert)
			if err != nil {
				return fmt.Errorf("error encoding signed certificate: %w", err)
			}

			if err := os.WriteFile(output, signedPEM, 0644); err != nil {
				return fmt.Errorf("error writing certificate file: %w", err)
			}

			fmt.Printf("Certificate signed successfully!\n")
			fmt.Printf("Serial Number: %s\n", signedCert.SerialNumber)
			fmt.Printf("Subject: %s\n", signedCert.Subject)
			fmt.Printf("Output: %s\n", output)

			return nil
		},
	}
}

// SignCertCmd signs a CSR with a CA to produce a certificate and returns an error instead of exiting
func SignCertCmd(args []string) error {
	return runLeafCommand(certSignCommand(), args)
}
```

- [ ] **Step 4: Replace `ValidateCertCmd`'s body**

Replace the entire `ValidateCertCmd` function (originally lines 98-167) with:

```go
func certValidateCommand() *cliv3.Command {
	var certFile, roots, intermediates, dnsName string
	var checkExpiration, allowExpired bool

	return &cliv3.Command{
		Name:  "validate",
		Usage: "Validate a certificate",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate file (required)", Destination: &certFile},
			&cliv3.StringFlag{Name: "roots", Usage: "Root CA certificate files (comma-separated)", Destination: &roots},
			&cliv3.StringFlag{Name: "intermediates", Usage: "Intermediate CA certificate files (comma-separated)", Destination: &intermediates},
			&cliv3.StringFlag{Name: "dns", Usage: "Hostname to verify", Destination: &dnsName},
			&cliv3.BoolFlag{Name: "check-expiration", Value: true, Usage: "Check certificate expiration", Destination: &checkExpiration},
			&cliv3.BoolFlag{Name: "allow-expired", Usage: "Allow expired certificates", Destination: &allowExpired},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}

			certPEM, err := os.ReadFile(certFile)
			if err != nil {
				return fmt.Errorf("error reading certificate file: %w", err)
			}

			certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
			if err != nil {
				return fmt.Errorf("error decoding certificate: %w", err)
			}

			rootCerts, err := loadCertificateFiles(roots)
			if err != nil {
				return fmt.Errorf("error loading root CA certificates: %w", err)
			}

			intermediateCerts, err := loadCertificateFiles(intermediates)
			if err != nil {
				return fmt.Errorf("error loading intermediate CA certificates: %w", err)
			}

			config := &cert.ValidationConfig{
				RootCAs:         rootCerts,
				IntermediateCAs: intermediateCerts,
				CheckExpiration: checkExpiration,
				DNSName:         dnsName,
				AllowExpired:    allowExpired,
			}

			result := validation.ValidateCertificate(certificate, config)

			fmt.Println("Validation Result:")
			fmt.Println("===================")
			fmt.Printf("Valid: %v\n", result.Valid)
			if len(result.Errors) > 0 {
				fmt.Printf("Errors: %s\n", strings.Join(result.Errors, "; "))
			}
			if len(result.Warnings) > 0 {
				fmt.Printf("Warnings: %s\n", strings.Join(result.Warnings, "; "))
			}
			fmt.Printf("Valid From: %s\n", result.ValidFrom)
			fmt.Printf("Valid Until: %s\n", result.ValidUntil)
			fmt.Printf("Expires In: %s\n", result.ExpiresIn)
			fmt.Printf("Signature Algorithm: %s\n", result.SignatureAlgorithm)
			fmt.Printf("Public Key Algorithm: %s\n", result.PublicKeyAlgorithm)
			fmt.Printf("Key Size: %d\n", result.KeySize)

			if !result.Valid {
				return fmt.Errorf("certificate validation failed: %s", strings.Join(result.Errors, "; "))
			}

			return nil
		},
	}
}

// ValidateCertCmd validates a certificate and returns an error instead of exiting
func ValidateCertCmd(args []string) error {
	return runLeafCommand(certValidateCommand(), args)
}
```

- [ ] **Step 5: Add the `cert` group constructor**

Add this new function to `internal/cli/misc_commands.go` (e.g. near the bottom of the file):

```go
func certCommand() *cliv3.Command {
	return &cliv3.Command{
		Name: "cert",
		Commands: []*cliv3.Command{
			certGenerateCommand(),
			certSignCommand(),
			certViewCommand(),
			certValidateCommand(),
		},
		SkipFlagParsing: true,
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			args := cmd.Args().Slice()
			if len(args) == 0 || isFlag(args[0]) {
				return GenerateCertCmd(args)
			}
			fmt.Fprintf(os.Stderr, "Unknown cert subcommand: %s\n", args[0])
			return ErrSilent
		},
	}
}
```

- [ ] **Step 6: Run the new tests and the full existing suite**

Run: `go test ./internal/cli/... -v`
Expected: PASS — the new `TestCertCommand*` tests pass, and every pre-existing test calling `SignCertCmd`/`ValidateCertCmd`/`SignCert`/`ValidateCert` (in `misc_commands_test.go`) still passes unchanged.

- [ ] **Step 7: Commit**

```bash
git add internal/cli/misc_commands.go internal/cli/cert_group_test.go
git commit -m "Migrate cert sign, cert validate, and assemble the cert command group"
```

---

## Task 5: Migrate `csr generate` and drop the `flag` import from `commands.go`

**Files:**
- Modify: `internal/cli/commands.go`

**Interfaces:**
- Consumes: `runLeafCommand` (Task 1), `GenerateCSRFromFileCmd` (existing, unchanged).
- Produces: `csrGenerateCommand() *cliv3.Command` — consumed by Task 6 (`csrCommand()` group).

- [ ] **Step 1: Replace `GenerateCSRCmd`'s body**

Replace the entire `GenerateCSRCmd` function (originally lines 432-502) with:

```go
func csrGenerateCommand() *cliv3.Command {
	var cn, country, org, dnsNames, keyType, csrOutput, keyOutput, configFile string
	var nonInteractive bool

	return &cliv3.Command{
		Name:  "generate",
		Usage: "Generate a CSR",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cn", Usage: "Common Name (required)", Destination: &cn},
			&cliv3.StringFlag{Name: "country", Value: "US", Usage: "Country", Destination: &country},
			&cliv3.StringFlag{Name: "org", Usage: "Organization", Destination: &org},
			&cliv3.StringFlag{Name: "dns", Usage: "DNS names (comma-separated)", Destination: &dnsNames},
			&cliv3.StringFlag{Name: "key-type", Value: "rsa2048", Usage: "Key type", Destination: &keyType},
			&cliv3.StringFlag{Name: "output", Value: "cert.csr", Usage: "Output CSR file", Destination: &csrOutput},
			&cliv3.StringFlag{Name: "key-output", Value: "cert.key", Usage: "Output private key file", Destination: &keyOutput},
			&cliv3.StringFlag{Name: "f", Usage: "Configuration file (YAML) for batch CSR generation", Destination: &configFile},
			&cliv3.BoolFlag{Name: "non-interactive", Usage: "Enable non-interactive mode (requires --cn)", Destination: &nonInteractive},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if configFile != "" {
				return GenerateCSRFromFileCmd(configFile)
			}

			if cn == "" && (nonInteractive || cn != "") {
				return fmt.Errorf("common Name (--cn) is required for non-interactive mode")
			}

			var dnsNamesList []string
			if dnsNames != "" {
				dnsNamesList = strings.Split(dnsNames, ",")
				for i, name := range dnsNamesList {
					dnsNamesList[i] = strings.TrimSpace(name)
				}
			}

			config := &cert.CSRConfig{
				CommonName:   cn,
				Country:      country,
				Organization: org,
				KeyType:      cert.KeyType(keyType),
				DNSNames:     dnsNamesList,
			}

			csr, privateKey, err := cert.GenerateCSR(config)
			if err != nil {
				return fmt.Errorf("error generating CSR: %w", err)
			}

			csrPEM, err := encoding.EncodeCSRToPEM(csr)
			if err != nil {
				return fmt.Errorf("error encoding CSR: %w", err)
			}

			keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
			if err != nil {
				return fmt.Errorf("error encoding key: %w", err)
			}

			if err := os.WriteFile(csrOutput, csrPEM, 0644); err != nil {
				return fmt.Errorf("error writing CSR file: %w", err)
			}

			if err := os.WriteFile(keyOutput, keyPEM, 0600); err != nil {
				return fmt.Errorf("error writing key file: %w", err)
			}

			fmt.Printf("CSR generated successfully!\n")
			fmt.Printf("CSR: %s\n", csrOutput)
			fmt.Printf("Private Key: %s\n", keyOutput)

			return nil
		},
	}
}

// GenerateCSRCmd generates a Certificate Signing Request and returns an error instead of exiting
func GenerateCSRCmd(args []string) error {
	return runLeafCommand(csrGenerateCommand(), args)
}
```

- [ ] **Step 2: Remove the now-unused `flag` import**

`commands.go` no longer has any `flag.NewFlagSet` calls (ca generate/view, cert generate/view, and csr generate were the only ones — all migrated). Remove `"flag"` from the import block.

- [ ] **Step 3: Run the full existing suite**

Run: `go build ./... && go test ./internal/cli/... -v`
Expected: PASS — `go build` confirms the unused import was fully removed; every pre-existing test calling `GenerateCSRCmd`/`GenerateCSR` (e.g. `TestGenerateCSR`, `TestGenerateCSRFromFile*`, `TestGenerateCSRWithSubjectFields`, `TestGenerateCSRWithEd25519`) passes unchanged.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/commands.go
git commit -m "Migrate csr generate to urfave/cli v3"
```

---

## Task 6: Migrate `csr view` and assemble the `csr` group (`internal/cli/misc_commands.go`)

**Files:**
- Modify: `internal/cli/misc_commands.go`
- Create: `internal/cli/csr_group_test.go`

**Interfaces:**
- Consumes: `csrGenerateCommand()` (Task 5), `runLeafCommand`, `isFlag`, `ErrSilent` (Task 1).
- Produces: `csrViewCommand() *cliv3.Command`, `csrCommand() *cliv3.Command` — `csrCommand()` consumed by Task 10 (root.go).

- [ ] **Step 1: Write the failing test for the group-dispatch behavior**

Create `internal/cli/csr_group_test.go`:

```go
package cli

import (
	"context"
	"errors"
	"testing"
)

func TestCSRCommandUnknownSubcommand(t *testing.T) {
	err := csrCommand().Run(context.Background(), []string{"csr", "bogus-subcommand"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/... -run TestCSRCommand -v`
Expected: FAIL — `csrCommand` is undefined (compile error).

- [ ] **Step 3: Replace `ViewCSRCmd`'s body**

Replace the entire `ViewCSRCmd` function (originally lines 178-220) with:

```go
func csrViewCommand() *cliv3.Command {
	var csrFile string
	return &cliv3.Command{
		Name:  "view",
		Usage: "View a CSR",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "csr", Usage: "CSR file (required)", Destination: &csrFile},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if csrFile == "" {
				return fmt.Errorf("CSR file (--csr) is required")
			}

			csrPEM, err := os.ReadFile(csrFile)
			if err != nil {
				return fmt.Errorf("error reading CSR file: %w", err)
			}

			csr, err := encoding.DecodeCSRFromPEM(csrPEM)
			if err != nil {
				return fmt.Errorf("error decoding CSR: %w", err)
			}

			fmt.Println("CSR Details:")
			fmt.Println("============")
			fmt.Printf("Subject: %s\n", csr.Subject)

			if len(csr.DNSNames) > 0 {
				fmt.Printf("DNS Names: %v\n", csr.DNSNames)
			}

			if len(csr.EmailAddresses) > 0 {
				fmt.Printf("Email Addresses: %v\n", csr.EmailAddresses)
			}

			if len(csr.IPAddresses) > 0 {
				fmt.Printf("IP Addresses: %v\n", csr.IPAddresses)
			}

			fmt.Printf("Signature Algorithm: %s\n", csr.SignatureAlgorithm)
			fmt.Printf("Public Key Algorithm: %s\n", csr.PublicKeyAlgorithm)

			return nil
		},
	}
}

// ViewCSRCmd displays CSR details and returns an error instead of exiting
func ViewCSRCmd(args []string) error {
	return runLeafCommand(csrViewCommand(), args)
}
```

- [ ] **Step 4: Add the `csr` group constructor**

```go
func csrCommand() *cliv3.Command {
	return &cliv3.Command{
		Name:            "csr",
		Commands:        []*cliv3.Command{csrGenerateCommand(), csrViewCommand()},
		SkipFlagParsing: true,
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			args := cmd.Args().Slice()
			if len(args) == 0 || isFlag(args[0]) {
				return GenerateCSRCmd(args)
			}
			fmt.Fprintf(os.Stderr, "Unknown csr subcommand: %s\n", args[0])
			return ErrSilent
		},
	}
}
```

- [ ] **Step 5: Run the new test and the full existing suite**

Run: `go test ./internal/cli/... -v`
Expected: PASS — `TestCSRCommandUnknownSubcommand` passes, and every pre-existing test calling `ViewCSRCmd`/`ViewCSR` still passes unchanged.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/misc_commands.go internal/cli/csr_group_test.go
git commit -m "Migrate csr view and assemble the csr command group"
```

---

## Task 7: Migrate `encode`/`decode` and drop the `flag` import from `misc_commands.go`

**Files:**
- Modify: `internal/cli/misc_commands.go`

**Interfaces:**
- Consumes: `runLeafCommand` (Task 1).
- Produces: `encodeCommand() *cliv3.Command`, `decodeCommand() *cliv3.Command` — both consumed by Task 10 (root.go, as standalone top-level commands).

- [ ] **Step 1: Replace `EncodeCertCmd`'s body**

Replace the entire `EncodeCertCmd` function (originally lines 230-302) with:

```go
func encodeCommand() *cliv3.Command {
	var input, output, format, keyFile, password string

	return &cliv3.Command{
		Name:  "encode",
		Usage: "Encode certificates/keys to different formats",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "input", Usage: "Input PEM certificate file (required)", Destination: &input},
			&cliv3.StringFlag{Name: "output", Usage: "Output file (required)", Destination: &output},
			&cliv3.StringFlag{Name: "format", Value: "der", Usage: "Output format (der or pkcs12)", Destination: &format},
			&cliv3.StringFlag{Name: "key", Usage: "Private key PEM file (required for pkcs12)", Destination: &keyFile},
			&cliv3.StringFlag{Name: "password", Usage: "Password (for pkcs12)", Destination: &password},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if input == "" {
				return fmt.Errorf("input file (--input) is required")
			}
			if output == "" {
				return fmt.Errorf("output file (--output) is required")
			}

			certPEM, err := os.ReadFile(input)
			if err != nil {
				return fmt.Errorf("error reading certificate file: %w", err)
			}

			certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
			if err != nil {
				return fmt.Errorf("error decoding certificate: %w", err)
			}

			switch format {
			case "der":
				derBytes, err := encoding.EncodeCertificateToDER(certificate)
				if err != nil {
					return fmt.Errorf("error encoding certificate to DER: %w", err)
				}

				if err := os.WriteFile(output, derBytes, 0644); err != nil {
					return fmt.Errorf("error writing output file: %w", err)
				}
			case "pkcs12":
				if keyFile == "" {
					return fmt.Errorf("private key file (--key) is required for pkcs12 format")
				}

				keyPEM, err := os.ReadFile(keyFile)
				if err != nil {
					return fmt.Errorf("error reading private key file: %w", err)
				}

				privateKey, err := encoding.DecodePrivateKeyFromPEM(keyPEM)
				if err != nil {
					return fmt.Errorf("error decoding private key: %w", err)
				}

				pfxData, err := encoding.EncodeToPKCS12(certificate, privateKey, password)
				if err != nil {
					return fmt.Errorf("error encoding to PKCS12: %w", err)
				}

				if err := os.WriteFile(output, pfxData, 0644); err != nil {
					return fmt.Errorf("error writing output file: %w", err)
				}
			default:
				return fmt.Errorf("unknown format: %s (expected der or pkcs12)", format)
			}

			fmt.Printf("Certificate encoded successfully!\n")
			fmt.Printf("Format: %s\n", format)
			fmt.Printf("Output: %s\n", output)

			return nil
		},
	}
}

// EncodeCertCmd converts a PEM certificate to DER or PKCS12 and returns an error instead of exiting
func EncodeCertCmd(args []string) error {
	return runLeafCommand(encodeCommand(), args)
}
```

- [ ] **Step 2: Replace `DecodeCertCmd`'s body**

Replace the entire `DecodeCertCmd` function (originally lines 313-386) with:

```go
func decodeCommand() *cliv3.Command {
	var input, output, keyOutput, format, password string

	return &cliv3.Command{
		Name:  "decode",
		Usage: "Decode certificates/keys from different formats",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "input", Usage: "Input file (required)", Destination: &input},
			&cliv3.StringFlag{Name: "output", Usage: "Output certificate PEM file (required)", Destination: &output},
			&cliv3.StringFlag{Name: "key-output", Usage: "Output private key PEM file (pkcs12 only)", Destination: &keyOutput},
			&cliv3.StringFlag{Name: "format", Value: "der", Usage: "Input format (der or pkcs12)", Destination: &format},
			&cliv3.StringFlag{Name: "password", Usage: "Password (for pkcs12)", Destination: &password},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if input == "" {
				return fmt.Errorf("input file (--input) is required")
			}
			if output == "" {
				return fmt.Errorf("output certificate file (--output) is required")
			}

			data, err := os.ReadFile(input)
			if err != nil {
				return fmt.Errorf("error reading input file: %w", err)
			}

			switch format {
			case "der":
				certificate, err := encoding.DecodeCertificateFromDER(data)
				if err != nil {
					return fmt.Errorf("error decoding certificate from DER: %w", err)
				}

				certPEM, err := encoding.EncodeCertificateToPEM(certificate)
				if err != nil {
					return fmt.Errorf("error encoding certificate to PEM: %w", err)
				}

				if err := os.WriteFile(output, certPEM, 0644); err != nil {
					return fmt.Errorf("error writing certificate file: %w", err)
				}
			case "pkcs12":
				certificate, privateKey, err := encoding.DecodeFromPKCS12(data, password)
				if err != nil {
					return fmt.Errorf("error decoding PKCS12: %w", err)
				}

				certPEM, err := encoding.EncodeCertificateToPEM(certificate)
				if err != nil {
					return fmt.Errorf("error encoding certificate to PEM: %w", err)
				}

				if err := os.WriteFile(output, certPEM, 0644); err != nil {
					return fmt.Errorf("error writing certificate file: %w", err)
				}

				if keyOutput != "" {
					keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
					if err != nil {
						return fmt.Errorf("error encoding private key to PEM: %w", err)
					}

					if err := os.WriteFile(keyOutput, keyPEM, 0600); err != nil {
						return fmt.Errorf("error writing private key file: %w", err)
					}
				}
			default:
				return fmt.Errorf("unknown format: %s (expected der or pkcs12)", format)
			}

			fmt.Printf("Certificate decoded successfully!\n")
			fmt.Printf("Format: %s\n", format)
			fmt.Printf("Output: %s\n", output)

			return nil
		},
	}
}

// DecodeCertCmd converts a DER or PKCS12 certificate back to PEM and returns an error instead of exiting
func DecodeCertCmd(args []string) error {
	return runLeafCommand(decodeCommand(), args)
}
```

- [ ] **Step 3: Remove the now-unused `flag` import**

`misc_commands.go` no longer has any `flag.NewFlagSet` calls (sign, validate, csr view, encode, decode were the only ones — all migrated). Remove `"flag"` from the import block.

- [ ] **Step 4: Run the full existing suite**

Run: `go build ./... && go test ./internal/cli/... -v`
Expected: PASS — `go build` confirms the unused import was fully removed; every pre-existing test calling `EncodeCertCmd`/`DecodeCertCmd`/`EncodeCert`/`DecodeCert` still passes unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/misc_commands.go
git commit -m "Migrate encode and decode to urfave/cli v3"
```

---

## Task 8: Migrate the `crl` group (`internal/cli/crl_commands.go`)

**Files:**
- Modify: `internal/cli/crl_commands.go`
- Create: `internal/cli/crl_group_test.go`

**Interfaces:**
- Consumes: `runLeafCommand`, `isFlag`, `ErrSilent` (Task 1).
- Produces: `crlGenerateCommand()`, `crlViewCommand()`, `crlCheckCommand()`, `crlCommand() *cliv3.Command` — consumed by Task 10 (root.go).

**Note:** unlike `ca`/`cert`/`csr`, `crl` has no default-to-generate behavior — no subcommand at all is a usage error (exit 1), matching today's `handleCRLCommand`.

- [ ] **Step 1: Write the failing tests for the group-dispatch behavior**

Create `internal/cli/crl_group_test.go`. This only asserts on the error/exit behavior (not the printed text) — `cmd/certifier/integration_test.go` already covers the exact printed text at the process level once Task 11 wires this into `main.go`:

```go
package cli

import (
	"context"
	"errors"
	"testing"
)

func TestCRLCommandNoSubcommand(t *testing.T) {
	err := crlCommand().Run(context.Background(), []string{"crl"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestCRLCommandUnknownSubcommand(t *testing.T) {
	err := crlCommand().Run(context.Background(), []string{"crl", "bogus"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestCRLCommandHelpFlagDoesNotError(t *testing.T) {
	err := crlCommand().Run(context.Background(), []string{"crl", "-h"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestCRLCommand -v`
Expected: FAIL — `crlCommand` is undefined (compile error).

- [ ] **Step 3: Replace `GenerateCRLCmd`'s body**

In `internal/cli/crl_commands.go`, add to the import block:

```go
	"context"

	cliv3 "github.com/urfave/cli/v3"
```

and remove `"flag"` (all three functions in this file are migrated together in this task).

Replace the entire `GenerateCRLCmd` function (originally lines 15-100) with:

```go
func crlGenerateCommand() *cliv3.Command {
	var caCertFile, caKeyFile, output, revoked, distributionURL string
	var validityDays, reason int
	var number int64

	return &cliv3.Command{
		Name:  "generate",
		Usage: "Generate a Certificate Revocation List",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (required)", Destination: &caCertFile},
			&cliv3.StringFlag{Name: "ca-key", Usage: "CA private key file (required)", Destination: &caKeyFile},
			&cliv3.StringFlag{Name: "output", Value: "crl.der", Usage: "Output CRL file", Destination: &output},
			&cliv3.IntFlag{Name: "validity", Value: 30, Usage: "Validity in days", Destination: &validityDays},
			&cliv3.Int64Flag{Name: "number", Value: 1, Usage: "CRL sequence number", Destination: &number},
			&cliv3.StringFlag{Name: "revoked", Usage: "Comma-separated list of revoked serial numbers (decimal)", Destination: &revoked},
			&cliv3.IntFlag{Name: "reason", Value: crl.ReasonUnspecified, Usage: "Revocation reason code applied to all entries in --revoked", Destination: &reason},
			&cliv3.StringFlag{Name: "distribution-url", Usage: "URL for CRL distribution", Destination: &distributionURL},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}

			if caKeyFile == "" {
				return fmt.Errorf("CA private key file (--ca-key) is required")
			}

			caCertPEM, err := os.ReadFile(caCertFile)
			if err != nil {
				return fmt.Errorf("error reading CA certificate: %w", err)
			}

			caCert, err := encoding.DecodeCertificateFromPEM(caCertPEM)
			if err != nil {
				return fmt.Errorf("error parsing CA certificate: %w", err)
			}

			caKeyPEM, err := os.ReadFile(caKeyFile)
			if err != nil {
				return fmt.Errorf("error reading CA key: %w", err)
			}

			caPrivateKey, err := encoding.DecodePrivateKeyFromPEM(caKeyPEM)
			if err != nil {
				return fmt.Errorf("error parsing CA key: %w", err)
			}

			var revokedList []*crl.RevokedCertificate
			if revoked != "" {
				now := time.Now()
				for _, serialStr := range strings.Split(revoked, ",") {
					serialStr = strings.TrimSpace(serialStr)
					serial, ok := new(big.Int).SetString(serialStr, 10)
					if !ok {
						return fmt.Errorf("invalid serial number: %s", serialStr)
					}

					revokedList = append(revokedList, &crl.RevokedCertificate{
						SerialNumber:     serial,
						RevocationTime:   now,
						RevocationReason: reason,
					})
				}
			}

			config := &crl.CRLConfig{
				CAKeyPair:       crl.NewKeyPair(caPrivateKey),
				CACertificate:   caCert,
				RevokedCerts:    revokedList,
				ValidityDays:    validityDays,
				Number:          number,
				DistributionURL: distributionURL,
			}

			crlBytes, err := crl.GenerateCRL(config)
			if err != nil {
				return fmt.Errorf("error generating CRL: %w", err)
			}

			if err := os.WriteFile(output, crlBytes, 0644); err != nil {
				return fmt.Errorf("error writing CRL file: %w", err)
			}

			fmt.Printf("CRL generated successfully!\n")
			fmt.Printf("CRL Number: %d\n", number)
			fmt.Printf("Output: %s\n", output)

			return nil
		},
	}
}

// GenerateCRLCmd generates a Certificate Revocation List and returns an error instead of exiting
func GenerateCRLCmd(args []string) error {
	return runLeafCommand(crlGenerateCommand(), args)
}
```

- [ ] **Step 4: Replace `ViewCRLCmd`'s body**

Replace the entire `ViewCRLCmd` function (originally lines 110-154) with:

```go
func crlViewCommand() *cliv3.Command {
	var crlFile string
	return &cliv3.Command{
		Name:  "view",
		Usage: "View CRL details",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "crl", Usage: "CRL file (required, DER-encoded)", Destination: &crlFile},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if crlFile == "" {
				return fmt.Errorf("CRL file (--crl) is required")
			}

			crlData, err := os.ReadFile(crlFile)
			if err != nil {
				return fmt.Errorf("error reading CRL file: %w", err)
			}

			revocationList, err := crl.ParseCRL(crlData)
			if err != nil {
				return fmt.Errorf("error parsing CRL: %w", err)
			}

			fmt.Println("CRL Details:")
			fmt.Println("============")
			fmt.Printf("Issuer: %s\n", revocationList.Issuer)
			fmt.Printf("Number: %s\n", revocationList.Number)
			fmt.Printf("This Update: %s\n", revocationList.ThisUpdate)
			fmt.Printf("Next Update: %s\n", revocationList.NextUpdate)

			if len(revocationList.RevokedCertificateEntries) == 0 {
				fmt.Println("No revoked certificates.")
				return nil
			}

			fmt.Printf("Revoked Certificates: %d\n", len(revocationList.RevokedCertificateEntries))
			for _, entry := range revocationList.RevokedCertificateEntries {
				fmt.Println("---")
				fmt.Printf("Serial Number: %s\n", entry.SerialNumber)
				fmt.Printf("Revocation Time: %s\n", entry.RevocationTime)
				fmt.Printf("Reason Code: %d\n", entry.ReasonCode)
			}

			return nil
		},
	}
}

// ViewCRLCmd displays CRL details and returns an error instead of exiting
func ViewCRLCmd(args []string) error {
	return runLeafCommand(crlViewCommand(), args)
}
```

- [ ] **Step 5: Replace `CheckCRLCmd`'s body**

Replace the entire `CheckCRLCmd` function (originally lines 164-219) with:

```go
func crlCheckCommand() *cliv3.Command {
	var crlFile, certFile string
	return &cliv3.Command{
		Name:  "check",
		Usage: "Check certificate revocation status against a CRL",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "crl", Usage: "CRL file (required, DER-encoded)", Destination: &crlFile},
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate file to check (required, PEM)", Destination: &certFile},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if crlFile == "" {
				return fmt.Errorf("CRL file (--crl) is required")
			}

			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}

			crlData, err := os.ReadFile(crlFile)
			if err != nil {
				return fmt.Errorf("error reading CRL file: %w", err)
			}

			revocationList, err := crl.ParseCRL(crlData)
			if err != nil {
				return fmt.Errorf("error parsing CRL: %w", err)
			}

			certPEM, err := os.ReadFile(certFile)
			if err != nil {
				return fmt.Errorf("error reading certificate file: %w", err)
			}

			certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
			if err != nil {
				return fmt.Errorf("error parsing certificate: %w", err)
			}

			fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)

			if crl.CheckRevocation(certificate, revocationList) {
				fmt.Println("Certificate is REVOKED")
			} else {
				fmt.Println("Certificate is NOT revoked")
			}

			return nil
		},
	}
}

// CheckCRLCmd checks whether a certificate is revoked according to a CRL and returns an error instead of exiting
func CheckCRLCmd(args []string) error {
	return runLeafCommand(crlCheckCommand(), args)
}
```

- [ ] **Step 6: Add the `crl` group constructor**

```go
func crlCommand() *cliv3.Command {
	return &cliv3.Command{
		Name: "crl",
		Commands: []*cliv3.Command{
			crlGenerateCommand(),
			crlViewCommand(),
			crlCheckCommand(),
		},
		SkipFlagParsing: true,
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			args := cmd.Args().Slice()
			if len(args) == 0 {
				fmt.Fprintf(os.Stderr, "Usage: certifier crl <generate|view|check> [options]\n")
				return ErrSilent
			}

			switch args[0] {
			case "-h", "--help":
				fmt.Println("Usage: certifier crl <generate|view|check> [options]")
				return nil
			default:
				fmt.Fprintf(os.Stderr, "Unknown crl subcommand: %s\n", args[0])
				return ErrSilent
			}
		},
	}
}
```

- [ ] **Step 7: Run the new tests and the full existing suite**

Run: `go build ./... && go test ./internal/cli/... -v`
Expected: PASS — the new `TestCRLCommand*` tests pass, `go build` confirms the `flag` import removal was clean, and every pre-existing test calling `GenerateCRLCmd`/`ViewCRLCmd`/`CheckCRLCmd`/`GenerateCRL`/`ViewCRL`/`CheckCRL` in `crl_commands_test.go` still passes unchanged.

- [ ] **Step 8: Commit**

```bash
git add internal/cli/crl_commands.go internal/cli/crl_group_test.go
git commit -m "Migrate crl command group to urfave/cli v3"
```

---

## Task 9: Migrate the `ocsp` group (`internal/cli/ocsp_commands.go`)

**Files:**
- Modify: `internal/cli/ocsp_commands.go`
- Create: `internal/cli/ocsp_group_test.go`

**Interfaces:**
- Consumes: `runLeafCommand`, `isFlag`, `ErrSilent` (Task 1), `loadCertAndIssuer` and `parseOCSPStatus` (existing helpers in this file, unchanged).
- Produces: `ocspResponseCommand()`, `ocspRequestCommand()`, `ocspVerifyCommand()`, `ocspCheckCommand()`, `ocspCommand() *cliv3.Command` — consumed by Task 10 (root.go).

**Note:** like `crl`, `ocsp` has no default subcommand — no subcommand at all is a usage error (exit 1).

- [ ] **Step 1: Write the failing tests for the group-dispatch behavior**

Create `internal/cli/ocsp_group_test.go`:

```go
package cli

import (
	"context"
	"errors"
	"testing"
)

func TestOCSPCommandNoSubcommand(t *testing.T) {
	err := ocspCommand().Run(context.Background(), []string{"ocsp"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestOCSPCommandUnknownSubcommand(t *testing.T) {
	err := ocspCommand().Run(context.Background(), []string{"ocsp", "bogus"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestOCSPCommandHelpFlagDoesNotError(t *testing.T) {
	err := ocspCommand().Run(context.Background(), []string{"ocsp", "-h"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestOCSPCommand -v`
Expected: FAIL — `ocspCommand` is undefined (compile error).

- [ ] **Step 3: Replace `GenerateOCSPResponseCmd`'s body**

In `internal/cli/ocsp_commands.go`, add to the import block:

```go
	"context"

	cliv3 "github.com/urfave/cli/v3"
```

and remove `"flag"` (all four functions in this file are migrated together in this task).

Replace the entire `GenerateOCSPResponseCmd` function (originally lines 37-116) with:

```go
func ocspResponseCommand() *cliv3.Command {
	var certFile, caCertFile, responderCertFile, responderKeyFile, statusStr, output string
	var revocationReason int

	return &cliv3.Command{
		Name:  "response",
		Usage: "Generate an OCSP response",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate file to create response for (required)", Destination: &certFile},
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (issuer) (required)", Destination: &caCertFile},
			&cliv3.StringFlag{Name: "responder-cert", Usage: "OCSP responder certificate file (defaults to --ca-cert)", Destination: &responderCertFile},
			&cliv3.StringFlag{Name: "responder-key", Usage: "OCSP responder private key file (required)", Destination: &responderKeyFile},
			&cliv3.StringFlag{Name: "status", Value: "good", Usage: "Certificate status: good, revoked, or unknown", Destination: &statusStr},
			&cliv3.IntFlag{Name: "revocation-reason", Usage: "Revocation reason code (used when --status=revoked)", Destination: &revocationReason},
			&cliv3.StringFlag{Name: "output", Value: "response.der", Usage: "Output OCSP response file", Destination: &output},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}
			if responderKeyFile == "" {
				return fmt.Errorf("responder private key file (--responder-key) is required")
			}

			certificate, caCert, err := loadCertAndIssuer(certFile, caCertFile)
			if err != nil {
				return err
			}

			responderCertificate := caCert
			if responderCertFile != "" {
				responderCertPEM, err := os.ReadFile(responderCertFile)
				if err != nil {
					return fmt.Errorf("error reading responder certificate: %w", err)
				}
				responderCertificate, err = encoding.DecodeCertificateFromPEM(responderCertPEM)
				if err != nil {
					return fmt.Errorf("error parsing responder certificate: %w", err)
				}
			}

			responderKeyPEM, err := os.ReadFile(responderKeyFile)
			if err != nil {
				return fmt.Errorf("error reading responder private key: %w", err)
			}
			responderKey, err := encoding.DecodePrivateKeyFromPEM(responderKeyPEM)
			if err != nil {
				return fmt.Errorf("error parsing responder private key: %w", err)
			}

			status, err := parseOCSPStatus(statusStr)
			if err != nil {
				return err
			}

			config := &ocsp.OCSPConfig{
				ResponderCertificate: responderCertificate,
				ResponderPrivateKey:  responderKey,
				CACertificate:        caCert,
				Certificate:          certificate,
				Status:               status,
				RevocationReason:     revocationReason,
			}

			respBytes, err := ocsp.GenerateOCSPResponse(config)
			if err != nil {
				return fmt.Errorf("error generating OCSP response: %w", err)
			}

			if err := os.WriteFile(output, respBytes, 0644); err != nil {
				return fmt.Errorf("error writing OCSP response file: %w", err)
			}

			fmt.Printf("OCSP response generated successfully!\n")
			fmt.Printf("Status: %s\n", statusStr)
			fmt.Printf("Output: %s\n", output)

			return nil
		},
	}
}

// GenerateOCSPResponseCmd generates an OCSP response and returns an error instead of exiting
func GenerateOCSPResponseCmd(args []string) error {
	return runLeafCommand(ocspResponseCommand(), args)
}
```

- [ ] **Step 4: Replace `CreateOCSPRequestCmd`'s body**

Replace the entire `CreateOCSPRequestCmd` function (originally lines 126-162) with:

```go
func ocspRequestCommand() *cliv3.Command {
	var certFile, caCertFile, output string

	return &cliv3.Command{
		Name:  "request",
		Usage: "Create an OCSP request",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate file to request status for (required)", Destination: &certFile},
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (issuer) (required)", Destination: &caCertFile},
			&cliv3.StringFlag{Name: "output", Value: "request.der", Usage: "Output OCSP request file", Destination: &output},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}

			certificate, caCert, err := loadCertAndIssuer(certFile, caCertFile)
			if err != nil {
				return err
			}

			reqBytes, err := ocsp.CreateOCSPRequest(certificate, caCert)
			if err != nil {
				return fmt.Errorf("error creating OCSP request: %w", err)
			}

			if err := os.WriteFile(output, reqBytes, 0644); err != nil {
				return fmt.Errorf("error writing OCSP request file: %w", err)
			}

			fmt.Printf("OCSP request created successfully!\n")
			fmt.Printf("Output: %s\n", output)

			return nil
		},
	}
}

// CreateOCSPRequestCmd creates an OCSP request and returns an error instead of exiting
func CreateOCSPRequestCmd(args []string) error {
	return runLeafCommand(ocspRequestCommand(), args)
}
```

- [ ] **Step 5: Replace `VerifyOCSPResponseCmd`'s body**

Replace the entire `VerifyOCSPResponseCmd` function (originally lines 172-224) with:

```go
func ocspVerifyCommand() *cliv3.Command {
	var responseFile, certFile, caCertFile string

	return &cliv3.Command{
		Name:  "verify",
		Usage: "Verify an OCSP response",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "response", Usage: "OCSP response file (DER-encoded) (required)", Destination: &responseFile},
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate to check status for (required)", Destination: &certFile},
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (issuer) (required)", Destination: &caCertFile},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if responseFile == "" {
				return fmt.Errorf("OCSP response file (--response) is required")
			}
			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}

			respBytes, err := os.ReadFile(responseFile)
			if err != nil {
				return fmt.Errorf("error reading OCSP response file: %w", err)
			}

			certificate, caCert, err := loadCertAndIssuer(certFile, caCertFile)
			if err != nil {
				return err
			}

			result, err := ocsp.VerifyOCSPResponse(respBytes, certificate, caCert)
			if err != nil {
				fmt.Printf("OCSP Response Verification: FAILED\n")
				return fmt.Errorf("error verifying OCSP response: %w", err)
			}

			fmt.Println("OCSP Response Verification:")
			fmt.Println("============================")
			fmt.Printf("Verified: %v\n", result["verified"])
			fmt.Printf("Status: %v\n", result["status"])
			fmt.Printf("Serial Number: %v\n", result["serialNumber"])
			fmt.Printf("This Update: %v\n", result["thisUpdate"])
			fmt.Printf("Next Update: %v\n", result["nextUpdate"])
			fmt.Printf("Produced At: %v\n", result["producedAt"])

			if revokedAt, ok := result["revokedAt"]; ok {
				fmt.Printf("Revoked At: %v\n", revokedAt)
				fmt.Printf("Revocation Reason: %v\n", result["revocationReason"])
			}

			return nil
		},
	}
}

// VerifyOCSPResponseCmd verifies an OCSP response and returns an error instead of exiting
func VerifyOCSPResponseCmd(args []string) error {
	return runLeafCommand(ocspVerifyCommand(), args)
}
```

- [ ] **Step 6: Replace `CheckOCSPStatusCmd`'s body**

Replace the entire `CheckOCSPStatusCmd` function (originally lines 236-278) with:

```go
func ocspCheckCommand() *cliv3.Command {
	var certFile, caCertFile, url string

	return &cliv3.Command{
		Name:  "check",
		Usage: "Check certificate status against a live OCSP responder",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate file to check (required)", Destination: &certFile},
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (issuer) (required)", Destination: &caCertFile},
			&cliv3.StringFlag{Name: "url", Usage: "OCSP responder URL (defaults to the certificate's AIA OCSP URL)", Destination: &url},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}

			certificate, caCert, err := loadCertAndIssuer(certFile, caCertFile)
			if err != nil {
				return err
			}

			status, err := ocsp.CheckCertificateStatus(certificate, caCert, url)
			if err != nil {
				return fmt.Errorf("error checking OCSP status: %w", err)
			}

			fmt.Println("OCSP Certificate Status:")
			fmt.Println("========================")
			fmt.Printf("Status: %s\n", status.Status)
			fmt.Printf("Serial Number: %s\n", status.Serial)
			fmt.Printf("Responder URL: %s\n", status.ResponderURL)
			fmt.Printf("This Update: %s\n", status.ThisUpdate)
			fmt.Printf("Next Update: %s\n", status.NextUpdate)
			fmt.Printf("Produced At: %s\n", status.ProducedAt)

			if status.Status == "revoked" {
				fmt.Printf("Revocation Time: %s\n", status.RevocationTime)
				fmt.Printf("Revocation Reason: %s\n", status.RevocationReason)
			}

			return nil
		},
	}
}

// CheckOCSPStatusCmd checks a certificate's revocation status against a live OCSP
// responder and returns an error instead of exiting.
func CheckOCSPStatusCmd(args []string) error {
	return runLeafCommand(ocspCheckCommand(), args)
}
```

- [ ] **Step 7: Add the `ocsp` group constructor**

```go
func ocspCommand() *cliv3.Command {
	return &cliv3.Command{
		Name: "ocsp",
		Commands: []*cliv3.Command{
			ocspResponseCommand(),
			ocspRequestCommand(),
			ocspVerifyCommand(),
			ocspCheckCommand(),
		},
		SkipFlagParsing: true,
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			args := cmd.Args().Slice()
			if len(args) == 0 {
				fmt.Fprintf(os.Stderr, "Usage: certifier ocsp <response|request|verify|check> [options]\n")
				return ErrSilent
			}

			switch args[0] {
			case "-h", "--help":
				fmt.Println("Usage: certifier ocsp <response|request|verify|check> [options]")
				return nil
			default:
				fmt.Fprintf(os.Stderr, "Unknown ocsp subcommand: %s\n", args[0])
				return ErrSilent
			}
		},
	}
}
```

- [ ] **Step 8: Run the new tests and the full existing suite**

Run: `go build ./... && go test ./internal/cli/... -v`
Expected: PASS — the new `TestOCSPCommand*` tests pass, `go build` confirms the `flag` import removal was clean, and every pre-existing test calling the four `*OCSP*Cmd`/exiting-wrapper functions in `ocsp_commands_test.go` still passes unchanged.

- [ ] **Step 9: Commit**

```bash
git add internal/cli/ocsp_commands.go internal/cli/ocsp_group_test.go
git commit -m "Migrate ocsp command group to urfave/cli v3"
```

---

## Task 10: Add `cli.RootCommand()` (`internal/cli/root.go`)

**Files:**
- Create: `internal/cli/root.go`
- Create: `internal/cli/root_test.go`

**Interfaces:**
- Consumes: `caCommand()`, `certCommand()`, `csrCommand()`, `crlCommand()`, `ocspCommand()`, `certValidateCommand()`, `certViewCommand()`, `encodeCommand()`, `decodeCommand()` (Tasks 2-9), `ErrSilent` (Task 1), `NewMenuMode()`/`DisplayMainMenu()` (existing, unchanged).
- Produces: `RootCommand() *cliv3.Command` (exported — consumed by Task 11's `cmd/certifier/main.go`).

This root command's own dispatch (help/version/unknown-command/no-args-menu) is verified via a compiled probe (see the design spec) to need `SkipFlagParsing: true` plus a fully manual `Action` — otherwise urfave's built-in `--help`/`-h` global flag intercepts those tokens before the custom logic ever runs, and passing zero args shows urfave's generic help instead of launching the interactive menu.

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/root_test.go`:

```go
package cli

import (
	"context"
	"errors"
	"testing"
)

func TestRootCommandUnknownCommand(t *testing.T) {
	err := RootCommand().Run(context.Background(), []string{"certifier", "bogus-command"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestRootCommandHelpDoesNotError(t *testing.T) {
	for _, args := range [][]string{
		{"certifier", "help"},
		{"certifier", "-h"},
		{"certifier", "--help"},
		{"certifier", "version"},
		{"certifier", "-v"},
		{"certifier", "--version"},
	} {
		if err := RootCommand().Run(context.Background(), args); err != nil {
			t.Errorf("Run(%v) error = %v, want nil", args, err)
		}
	}
}

func TestRootCommandRoutesToCAGroup(t *testing.T) {
	err := RootCommand().Run(context.Background(), []string{"certifier", "ca", "bogus-subcommand"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent (routed through to the ca group's own dispatch)", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/cli/... -run TestRootCommand -v`
Expected: FAIL — `RootCommand` is undefined (compile error).

- [ ] **Step 3: Implement `RootCommand` and `printUsage`**

Create `internal/cli/root.go`:

```go
package cli

import (
	"context"
	"fmt"
	"os"

	cliv3 "github.com/urfave/cli/v3"
)

// RootCommand builds the full certifier command tree.
func RootCommand() *cliv3.Command {
	return &cliv3.Command{
		Name: "certifier",
		Commands: []*cliv3.Command{
			caCommand(),
			certCommand(),
			csrCommand(),
			certValidateCommand(),
			certViewCommand(),
			encodeCommand(),
			decodeCommand(),
			crlCommand(),
			ocspCommand(),
		},
		SkipFlagParsing: true,
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			args := cmd.Args().Slice()
			if len(args) == 0 {
				menu := NewMenuMode()
				menu.DisplayMainMenu()
				return nil
			}

			switch args[0] {
			case "help", "-h", "--help":
				printUsage()
				return nil
			case "version", "-v", "--version":
				fmt.Println("certifier version 1.0.0")
				return nil
			default:
				fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
				printUsage()
				return ErrSilent
			}
		},
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `certifier - X.509 Certificate Management Tool

Usage:
  certifier <command> [options]

Commands:
  ca       - Certificate Authority operations
             certifier ca generate - Generate a CA certificate
             certifier ca view - View a CA certificate

  cert     - Certificate operations
             certifier cert generate - Generate a certificate
             certifier cert sign - Sign a certificate with CA
             certifier cert view - View certificate details
             certifier cert validate - Validate a certificate

  csr      - Certificate Signing Request operations
             certifier csr generate - Generate a CSR
             certifier csr view - View a CSR

  validate - Validate certificates and chains
  view     - View certificate details
  encode   - Encode certificates/keys to different formats
  decode   - Decode certificates/keys from different formats
  crl      - Certificate Revocation List operations
  ocsp     - OCSP operations

Options:
  -h, --help     Show this help message
  -v, --version  Show version

Examples:
  # Generate a CA certificate
  certifier ca generate --cn "My CA" --output ca.crt --key-output ca.key

  # Generate a server certificate
  certifier cert generate --cn "example.com" --output server.crt --key-output server.key

  # Validate a certificate
  certifier cert validate --cert server.crt --ca-cert ca.crt

  # View certificate details
  certifier cert view --cert server.crt

For more help on a specific command, use:
  certifier <command> -h
`)
}
```

Note: `certValidateCommand()` and `certViewCommand()` are registered here with `Name: "validate"` and `Name: "view"` respectively (already set that way inside their constructors from Tasks 3-4) — this is exactly the top-level `validate`≡`cert validate`, `view`≡`cert view` aliasing the spec calls for, with zero extra code, since each call to the constructor builds an independent `*cliv3.Command` instance.

- [ ] **Step 4: Run the new tests**

Run: `go test ./internal/cli/... -run TestRootCommand -v`
Expected: PASS.

- [ ] **Step 5: Run the full existing suite**

Run: `go build ./... && go test ./...`
Expected: PASS — nothing outside `internal/cli` references `RootCommand` yet, so this only confirms no regressions.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/root.go internal/cli/root_test.go
git commit -m "Add cli.RootCommand assembling the full certifier command tree"
```

---

## Task 11: Rewrite `cmd/certifier/main.go` and remove dead dispatch code

**Files:**
- Modify: `cmd/certifier/main.go` (full rewrite)
- Delete: `cmd/certifier/main_test.go`

**Interfaces:**
- Consumes: `cli.RootCommand()`, `cli.ErrSilent` (Task 10, Task 1).

`cmd/certifier/main_test.go` only tests `isFlag` and `printUsage` as they existed in package `main` — both are being deleted from `main.go` (an equivalent `isFlag` now lives, unexported, in `internal/cli`; `printUsage` moved to `internal/cli/root.go` in Task 10 and is already covered indirectly by `TestRootCommandUnknownCommand`/`TestRootCommandHelpDoesNotError`). Deleting the file (rather than editing it) is correct since every test in it targets removed package-`main` identifiers.

- [ ] **Step 1: Replace the entire contents of `cmd/certifier/main.go`**

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/0x524a/certifier/internal/cli"
)

func main() {
	cmd := cli.RootCommand()
	err := cmd.Run(context.Background(), os.Args)
	if err == nil {
		return
	}
	if !errors.Is(err, cli.ErrSilent) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	os.Exit(1)
}
```

This replaces all 307 lines of the original file: the `isFlag` function, `printUsage`, every `handleXxxCommand` function, and every thin per-command passthrough function (`generateCA`, `viewCA`, `generateCert`, `signCert`, `viewCert`, `validateCert`, `generateCSR`, `viewCSR`, `encodeCert`, `decodeCert`, `generateCRL`, `viewCRL`, `checkCRL`, `generateOCSPResponse`, `createOCSPRequest`, `verifyOCSPResponse`, `checkOCSPStatus`) are all removed — their logic now lives in `internal/cli`'s command constructors and is reached through the `RootCommand()` tree.

- [ ] **Step 2: Delete the now-dead test file**

```bash
rm cmd/certifier/main_test.go
```

- [ ] **Step 3: Build and run the package-level tests**

Run: `go build ./... && go test ./cmd/certifier/...`
Expected: PASS. (`TestIsFlag`, `TestIsFlagVariations`, `TestPrintUsage` are gone along with the file; `TestTopLevelCommands`, `TestCAInteractiveNoHang`, `TestCASubcommands`, and `TestFullWorkflow` in `integration_test.go` exercise the real compiled binary and are the true test of this task — run them now.)

Run: `go test ./cmd/certifier/... -v -run 'TestTopLevelCommands|TestCAInteractiveNoHang|TestCASubcommands|TestFullWorkflow'`
Expected: PASS — every case, including:
- `help`/`-h`/`--help` (exit 0, stderr contains the usage banner)
- `version`/`-v`/`--version` (exit 0, stdout `certifier version 1.0.0`)
- unknown command (exit 1, stderr contains `Unknown command: bogus-command` and the usage banner)
- `ca` with no subcommand and empty stdin (fails fast, non-zero exit, no hang)
- `ca generate --non-interactive` missing `--cn` (exit 1, mentions "Common Name")
- `ca generate`/`ca view` success paths
- `ca bogus-subcommand` (exit 1, stderr contains `Unknown ca subcommand`)
- the full cert/csr/crl/ocsp workflow chain, including `crl`/`ocsp` with no subcommand (exit 1, usage message), bogus subcommand (exit 1), and `-h`/`--help` (exit 0, stdout usage message)

- [ ] **Step 4: Commit**

```bash
git add cmd/certifier/main.go
git rm cmd/certifier/main_test.go
git commit -m "Replace hand-rolled main.go dispatch with cli.RootCommand"
```

---

## Task 12: Full regression pass, manual smoke test, and final cleanup

**Files:** none (verification only, plus incidental fixes if regressions are found)

- [ ] **Step 1: Full automated test suite**

Run:
```bash
go build ./...
go test ./...
gofmt -l .
go vet ./...
```
Expected: `go test` all PASS, `gofmt -l .` prints nothing, `go vet` reports nothing. If any pre-existing test fails, this is a real regression (per the spec's testing strategy: a failure caused by a changed flag default, required-flag check, or generation/validation error message must be fixed in the migrated code, not papered over in the test).

- [ ] **Step 2: Manual binary smoke test**

Build once: `go build -o /tmp/certifier-smoke ./cmd/certifier`

In a scratch directory, run through the full command tree from the spec's table and confirm each behaves as expected (success paths produce the expected files/output; error paths produce the expected message and a non-zero exit code; `-h`/`--help` on every leaf command now exits 0 and shows real per-command usage, including the new `Usage` line for that command, e.g. `certifier crl generate -h` should show "Generate a Certificate Revocation List" rather than a generic placeholder):

```bash
cd $(mktemp -d)
/tmp/certifier-smoke -h
/tmp/certifier-smoke --version
/tmp/certifier-smoke bogus-command; echo "exit=$?"

/tmp/certifier-smoke ca generate --cn "Test CA" --non-interactive --output ca.crt --key-output ca.key
/tmp/certifier-smoke ca generate -h; echo "exit=$?"
/tmp/certifier-smoke ca view --cert ca.crt
/tmp/certifier-smoke ca bogus; echo "exit=$?"

/tmp/certifier-smoke cert generate --cn example.com --non-interactive --output server.crt --key-output server.key
/tmp/certifier-smoke cert sign -h; echo "exit=$?"
/tmp/certifier-smoke cert view --cert server.crt
/tmp/certifier-smoke cert validate --cert server.crt --roots ca.crt
/tmp/certifier-smoke validate --cert server.crt --roots ca.crt
/tmp/certifier-smoke view --cert server.crt

/tmp/certifier-smoke csr generate --cn example.com --non-interactive --output test.csr --key-output test.key
/tmp/certifier-smoke csr view --csr test.csr

/tmp/certifier-smoke cert sign --csr test.csr --ca-cert ca.crt --ca-key ca.key --output signed.crt

/tmp/certifier-smoke encode --input server.crt --output server.der --format der
/tmp/certifier-smoke decode --input server.der --output roundtrip.crt --format der

/tmp/certifier-smoke crl generate --ca-cert ca.crt --ca-key ca.key --output test.crl --revoked 1,2,3
/tmp/certifier-smoke crl view --crl test.crl
/tmp/certifier-smoke crl check --crl test.crl --cert server.crt
/tmp/certifier-smoke crl; echo "exit=$?"
/tmp/certifier-smoke crl -h; echo "exit=$?"

/tmp/certifier-smoke ocsp request --cert server.crt --ca-cert ca.crt --output req.der
/tmp/certifier-smoke ocsp response --cert server.crt --ca-cert ca.crt --responder-key ca.key --output resp.der
/tmp/certifier-smoke ocsp verify --response resp.der --cert server.crt --ca-cert ca.crt
/tmp/certifier-smoke ocsp; echo "exit=$?"
```

Expected: every command above succeeds or fails exactly as the corresponding case in `cmd/certifier/integration_test.go` / the spec's command table describes, and every `-h` invocation now exits 0 with a real, specific one-line description instead of erroring or showing a generic placeholder.

- [ ] **Step 3: Update `README.md` and `BATCH_GENERATION.md` if any flag names or examples changed**

They should not have — every flag name, default, and required-ness was preserved exactly per the spec. Skim both files' CLI examples once against the smoke-test output above to confirm; no edits are expected.

- [ ] **Step 4: Final commit**

If Step 1-3 required any fixes, commit them now:

```bash
git add -A
git commit -m "Fix regressions found during urfave/cli v3 migration regression pass"
```

If no fixes were needed, there is nothing to commit — the migration is complete as of Task 11's commit.
