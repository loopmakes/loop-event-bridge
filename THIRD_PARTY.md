# Third-party dependencies

Dependencies are fetched through the Go module system; their source is not vendored in this repository. Exact direct and transitive versions and checksums are recorded in `go.mod` and `go.sum`.

Direct dependencies:

- [Ory Fosite v0.49.0](https://github.com/ory/fosite/tree/v0.49.0), [Apache License 2.0](https://github.com/ory/fosite/blob/v0.49.0/LICENSE): OAuth protocol engine
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto), [BSD 3-Clause](https://cs.opensource.google/go/x/crypto/+/master:LICENSE): password hashing

The implementation also uses Go's standard library. Container builds use the official `golang:1.27.1-alpine` builder and copy its CA trust bundle into a scratch runtime.

Transitive dependencies retain their own licenses. If you distribute a built binary or container, review and include the applicable third-party notices for that distribution. The source repository's own license does not replace dependency licenses.

The initial Fosite transitive versions were updated to address Go vulnerability database findings before this source was prepared. Re-run `govulncheck ./...` when upgrading or deploying; a scan is not a security audit.
