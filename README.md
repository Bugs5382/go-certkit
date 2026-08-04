# go-certkit 🔐

> Parse, inspect and convert X.509 certificate/key containers — PEM, DER, PKCS#12, PKCS#7 and JKS/JCEKS — through one normalized `Bundle` type.

## 📦 Install

```bash
go get github.com/Bugs5382/go-certkit
```

## 🚀 Usage

`Parse` accepts any supported container format and normalizes it to a
`Bundle`: a leaf certificate, an optional private key, an optional
intermediate/root chain, and derived metadata (subject, issuer, SANs,
validity window, fingerprint, key algorithm/size).

```go
data, err := os.ReadFile("site.p12")
if err != nil {
    log.Fatal(err)
}

bundle, err := certkit.Parse(data, "changeit")
if err != nil {
    log.Fatal(err)
}

fmt.Println(bundle.Meta.Subject, bundle.Meta.NotAfter)
```

`Export` reassembles a `Bundle` into any supported format, optionally
re-encrypting it under a new passphrase:

```go
pfx, err := certkit.Export(bundle, certkit.PKCS12, "new-passphrase")
if err != nil {
    log.Fatal(err)
}
```

### 🧩 Formats

| Format         | Contains                          |
|----------------|------------------------------------|
| `PKCS12`       | leaf + key + chain, encrypted      |
| `PEMBundle`    | leaf + key + chain, PEM            |
| `PEMCertOnly`  | leaf only, PEM                     |
| `PEMKeyOnly`   | key only, PEM                      |
| `PEMFullchain` | leaf + chain, PEM (no key)         |
| `DER`          | leaf only, raw ASN.1               |
| `PKCS7`        | leaf + chain, no key (`.p7b/.p7c`) |
| `JKS`          | Java KeyStore (JKS or JCEKS)       |

`DetectFormat` returns a best-effort guess of a blob's format; `Parse`
dispatches on that hint and falls back to trying every parser if the hint is
ambiguous or wrong.

### 🗂️ Multi-entry containers

A JKS/JCEKS keystore or a PKCS#7 bag can hold more than one distinct entry.
When that happens, `Parse` returns `*certkit.ErrMultipleEntries`, carrying
each entry's alias/subject:

```go
bundle, err := certkit.Parse(jksData, "changeit")
var multi *certkit.ErrMultipleEntries
if errors.As(err, &multi) {
    // present multi.Aliases to the caller, then:
    bundle, err = certkit.ParseEntry(jksData, "changeit", multi.Aliases[0])
}
```

### ⚠️ Errors

- `ErrWrongPassphrase` — the supplied passphrase failed to decrypt the key,
  PKCS#12 archive or JKS/JCEKS keystore.
- `ErrUnrecognizedFormat` — the input didn't match any supported format.
- `ErrNoPrivateKey` — a key-bearing export (`PKCS12`, `JKS`, `PEMBundle`,
  `PEMKeyOnly`) needs a private key, but the `Bundle` has none.
- `ErrMultipleEntries{Aliases []string}` — see above.

## 📄 License

MIT — see [LICENSE](LICENSE).
