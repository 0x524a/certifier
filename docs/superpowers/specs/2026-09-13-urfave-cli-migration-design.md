# Migrate CLI dispatch/flag-parsing to urfave/cli v3

Date: 2026-09-13

## Goal

Replace the hand-rolled `os.Args` switch in `cmd/certifier/main.go` and the
per-command `flag.NewFlagSet` blocks in `internal/cli/*.go` with a
`github.com/urfave/cli/v3` command tree. This is plumbing only: certificate
generation/validation/view/encode/decode/CRL/OCSP logic, and the bespoke
interactive menu system, are untouched — just re-wired to read flag values
from urfave/cli instead of the standard `flag` package.

**Primary motivation:** today, `-h`/`--help` handling is inconsistent across
commands (we already found and fixed one class of this bug: `crl -h` /
`ocsp -h` didn't work at all) because every command hand-rolls its own flag
parsing and usage text. A single framework gives us that consistency for
free, going forward, instead of us hand-maintaining it per command.

## Non-goals

- No change to certificate/CSR/CRL/OCSP business logic (`pkg/cert`,
  `pkg/validation`, `pkg/crl`, `pkg/ocsp`, `pkg/encoding`, `pkg/config`).
- No change to the interactive REPL menu (`internal/cli/menu.go`,
  `internal/cli/interactive.go`) or to the "no subcommand / flag-first arg
  falls into interactive generate" behavior for `ca`/`cert`/`csr`. It gets
  invoked from urfave/cli `Action` functions the same way it's invoked from
  the current hand-rolled dispatch today.
- Not chasing byte-for-byte identical `--help` banner formatting. Flag
  names, defaults, and required-ness are preserved; the exact page layout of
  top-level `--help` output is allowed to become urfave/cli's own template
  and gets polished after the fact, not gated on now.

## Command tree

Top level (`cmd/certifier/main.go` today, becoming the root `cli.Command`):

| Today | Becomes |
|---|---|
| `ca`, `cert`, `csr`, `crl`, `ocsp` | subcommands with their own sub-subcommands |
| `validate`, `view`, `encode`, `decode` | top-level commands (aliases: `validate`≡`cert validate`, `view`≡`cert view`) |
| `help`, `-h`, `--help` (bare word or flag) | urfave/cli's built-in help |
| `version`, `-v`, `--version` | urfave/cli's built-in version flag/command, `Version: "1.0.0"`, custom `VersionPrinter` to keep the exact `certifier version 1.0.0` line |
| unknown command → usage + exit 1 | urfave/cli's default "unknown command" handling |

Subcommand groups and their flags (unchanged names/defaults/usage text,
just moved from `flag.String/Bool/Int` to `cli.StringFlag/BoolFlag/IntFlag`):

- **`ca generate`**: `cn` (required), `country` (US), `key-output`
  (ca.key), `key-type` (rsa2048), `locality`, `non-interactive`, `org`,
  `ou`, `output` (ca.crt), `province`, `validity` (3650)
- **`ca view`**: `cert` (required)
- **`cert generate`**: `ca-cert`, `ca-key`, `cert-type` (server), `cn`
  (required), `country` (US), `dns`, `ext-oid`, `f` (batch YAML),
  `ip`, `key-output` (cert.key), `key-type` (rsa2048), `locality`,
  `non-interactive`, `ocsp-url`, `org`, `ou`, `output` (cert.crt),
  `province`, `validity` (365)
- **`cert sign`**: `ca-cert` (required), `ca-key` (required), `csr`
  (required), `output` (signed.crt), `validity` (365)
- **`cert view`** / **`view`**: `cert` (required)
- **`cert validate`** / **`validate`**: `allow-expired`, `cert`
  (required), `check-expiration` (true), `dns`, `intermediates`, `roots`
- **`csr generate`**: `cn` (required), `country` (US), `dns`, `f` (batch
  YAML), `key-output` (cert.key), `key-type` (rsa2048),
  `non-interactive`, `org`, `output` (cert.csr)
- **`csr view`**: `csr` (required)
- **`encode`**: `format` (der), `input` (required), `key`, `output`
  (required), `password`
- **`decode`**: `format` (der), `input` (required), `key-output`,
  `output` (required), `password`
- **`crl generate`**: `ca-cert` (required), `ca-key` (required),
  `distribution-url`, `number` (1), `output` (crl.der), `reason`,
  `revoked`, `validity` (30)
- **`crl view`**: `crl` (required)
- **`crl check`**: `cert` (required), `crl` (required)
- **`ocsp response`**: `ca-cert` (required), `cert` (required), `output`
  (response.der), `responder-cert`, `responder-key` (required),
  `revocation-reason`, `status` (good)
- **`ocsp request`**: `ca-cert` (required), `cert` (required), `output`
  (request.der)
- **`ocsp verify`**: `ca-cert` (required), `cert` (required), `response`
  (required)
- **`ocsp check`**: `ca-cert` (required), `cert` (required), `url`

## Key design decisions

**"Required" flags stay hand-validated, not `cli.StringFlag{Required: true}`.**
Today, a missing `--cn` on `ca generate` doesn't hard-fail — it falls into
interactive prompting unless `--non-interactive` is set, in which case it
returns the specific message `"common Name (--cn) is required for
non-interactive mode"`. urfave/cli's own `Required: true` produces a
different error shape and would short-circuit before our interactive
fallback ever runs. So required-ness keeps being checked by hand inside each
command's `Action`, exactly as it is today inside each `*Cmd` function —
only the source of the flag value changes (`cmd.String("cn")` via
`*cli.Command` instead of `*flag.FlagSet`).

**Batch config (`-f`) and non-interactive/interactive branching are
unchanged.** These live below the flag-parsing layer today and stay there.

**`crl`/`ocsp` don't get a default subcommand** (there's no single "obvious"
default the way `generate` is for `ca`/`cert`/`csr`), matching today's
behavior where `certifier crl` with no subcommand prints usage and exits 1.

**`ca`/`cert`/`csr` default-to-generate behavior**: implemented via
urfave/cli v3's `DefaultCommand` on those three parent commands (falls back
to a manual `Action` on the parent that shells out to the generate command's
logic if `DefaultCommand` doesn't cover the "first arg is a flag, not a
subcommand name" case cleanly — confirmed at implementation time).

## Migration order (for the implementation plan)

Single PR, but built and verified in this order so failures are localized:
1. `go.mod`: add `github.com/urfave/cli/v3`.
2. Top-level root command + `ca`/`ca generate`/`ca view` (smallest group,
   proves the pattern end-to-end: flags, required-value validation,
   interactive fallback, `-h`, exit codes).
3. `cert` group (largest: generate/sign/view/validate), then `csr` group.
4. `validate`/`view`/`encode`/`decode` top-level aliases.
5. `crl` group, then `ocsp` group.
6. Remove the now-dead `cmd/certifier/main.go` dispatch code and the
   per-command `flag.NewFlagSet` blocks in `internal/cli/*.go`.
7. Full regression: `go test ./...`, plus the manual end-to-end pass we ran
   earlier in this session (every command/flag combination against the
   built binary) to catch anything the test suite doesn't assert on.

## Testing strategy

- Existing unit tests in `internal/cli/*_test.go` that call `*Cmd` functions
  directly (e.g. `GenerateCACmd(args []string) error`) get updated to
  construct/invoke the urfave/cli `Command` instead of a raw arg slice,
  keeping the same assertions on returned errors and file output where the
  string being asserted on is business logic (e.g. `"CA certificate is
  required"`), and relaxed/updated where the string is purely a flag-parsing
  artifact (e.g. `"error parsing flags: %w"`).
- Black-box integration tests in `cmd/certifier/integration_test.go` (spawn
  the real binary, assert stdout/stderr/exit code) are the source of truth
  for "did behavior actually change" — run these after every migration step
  in the order above, not just at the end.
- Per the "preserve exact behavior, polish later" call: a test failing only
  because of top-level `--help` banner formatting or `version`-flag-vs-word
  phrasing gets updated to match the new (still-correct) output rather than
  blocking the migration; a test failing because a flag default, required
  check, or generation/validation error message changed is a real
  regression and gets fixed in code, not in the test.

## Open items to resolve during implementation (not spec-blocking)

- Whether urfave/cli v3's `DefaultCommand` cleanly covers "first arg looks
  like a flag, not a subcommand name" (e.g. `certifier ca --cn X`) or
  whether that needs a manual `Action` fallback, as noted above.
- Exact top-level `--help` banner template (verbatim vs. urfave/cli
  default) — cosmetic, deferred.
