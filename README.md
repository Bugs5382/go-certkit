# go-certkit

> Parse, inspect and convert X.509 certificate/key containers (PEM, DER, PKCS#12, PKCS#7, JKS/JCEKS) through one normalized `Bundle` type.

## Install

```bash
go get github.com/Bugs5382/go-certkit
```

## Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # gofmt check + golangci-lint + yamllint
task license  # inject MIT headers (golic)
```

Commit discipline, AI-tell/emoji blocking, and the pre-push gofmt/vet/lint/test gate are enforced
by the governance hooks. Install them once per clone:

```bash
bash .claude/hooks/install.sh
```

## License

MIT (c) 2026 Shane
