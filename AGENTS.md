# AGENTS.md - go-certkit

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

A small, dependency-light Go library that parses, inspects and converts X.509 certificate/key
containers -- PEM, DER, PKCS#12, PKCS#7 and JKS/JCEKS -- through one normalized `Bundle` type. It
ships as a library only (no service, CLI or action).

## Using go-certkit

Consumers depend on two entry points and one value type:

- `Parse(data []byte, passphrase string) (Bundle, error)` normalizes any supported container into a
  `Bundle` (leaf PEM, optional key PEM, chain PEM, derived `Meta`). Multi-entry keystores/bags
  return `*ErrMultipleEntries`; select one with `ParseEntry`.
- `Export(b Bundle, f Format, newPassphrase string) ([]byte, error)` reassembles a `Bundle` into any
  supported `Format`, re-encrypting where the format supports it.
- The `Bundle`, `Meta`, `Format` names and the sentinel errors (`ErrWrongPassphrase`,
  `ErrUnrecognizedFormat`, `ErrNoPrivateKey`, `ErrMultipleEntries`) are the public contract -- keep
  them stable.

## Layout

- `format.go` - `Format` enum + `DetectFormat`.
- `bundle.go` - `Bundle`, `Meta` + `metaFromLeaf`.
- `parse.go` - `Parse` / `ParseEntry` + per-format parsers.
- `export.go` - `Export` + per-format assemblers.
- `errors.go` - sentinel errors.
- `pkcs8crypt.go` - minimal PBES2 encrypt/decrypt for encrypted PKCS#8 PEM keys (stdlib only).
- `*_test.go` - fixtures generated in-process (no committed binary testdata).

## Build, test, lint

- Build: `task build` (`go build ./...`)
- Test: `task test` (`go test ./...`); fixtures are generated in-test, no external services needed.
- Lint: `task lint` (gofmt check + `golangci-lint run` + `yamllint`)
- License headers: `task license` (verify) / `task license:fix` (inject MIT headers via golic)

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- PUBLIC repo: generic cryptography only. No organization names, internal hostnames, or product
  references anywhere.
- Keep functions under gocyclo 15; the parsers dispatch through small helpers for this reason.
