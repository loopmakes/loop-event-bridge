# Third-party dependencies

Dependencies are fetched through the Go module system; their source is not vendored in this repository. Exact direct and transitive versions and checksums are recorded in `go.mod` and `go.sum`.

Direct dependencies:

- [Ory Fosite v0.49.0](https://github.com/ory/fosite/tree/v0.49.0), [Apache License 2.0](https://github.com/ory/fosite/blob/v0.49.0/LICENSE): OAuth protocol engine
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto), [BSD 3-Clause](https://cs.opensource.google/go/x/crypto/+/master:LICENSE): password hashing

The implementation also uses Go's standard library. Container builds use the official `golang:1.27.1-alpine` builder and copy its CA trust bundle into a scratch runtime.

Transitive dependencies retain their own licenses. If you distribute a built binary or container, review and include the applicable third-party notices for that distribution. The source repository's own license does not replace dependency licenses.

The initial Fosite transitive versions were updated to address Go vulnerability database findings before this source was prepared. Re-run `govulncheck ./...` when upgrading or deploying; a scan is not a security audit.

## Optional Proton source

- [`github.com/ProtonMail/go-proton-api` at `390fd389be646b9ac79bc848f57a198e0573c517`](https://github.com/ProtonMail/go-proton-api/tree/390fd389be646b9ac79bc848f57a198e0573c517), pinned as `v0.0.0-20261002101729-390fd389be64`: Proton-maintained direct API client, [MIT license](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/LICENSE), copyright 2020 James Houlahan and 2022 Proton AG
- [`golang.org/x/term v0.46.0`](https://pkg.go.dev/golang.org/x/term@v0.46.0), [BSD 3-Clause](https://cs.opensource.google/go/x/term/+/refs/tags/v0.46.0:LICENSE): no-echo operator terminal input
- [`golang.org/x/sys v0.48.0`](https://pkg.go.dev/golang.org/x/sys@v0.48.0), [BSD 3-Clause](https://cs.opensource.google/go/x/sys/+/refs/tags/v0.48.0:LICENSE): Unix private-file handling and advisory session locks

The root module mirrors the official Proton client's `go.mod` replacement of `github.com/go-resty/resty/v2` with [`github.com/ProtonMail/resty/v2 v2.0.0-20250929142426-e3dc6308c80b`](https://github.com/ProtonMail/resty/tree/e3dc6308c80b), [MIT license](https://github.com/ProtonMail/resty/blob/e3dc6308c80b/LICENSE). Dependency-module replace directives do not propagate to consumers; this explicit replacement keeps the reviewed Proton HTTP behavior consistent with upstream. Proton's client requires Go 1.26.1 or newer.

Proton and its transitive cryptographic/email dependencies are linked into the binary even when the source is disabled. Disabling the source prevents credential reads and network/session initialization; it does not remove compiled dependencies or their license obligations. See upstream's [copying/dependency notes](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/COPYING_NOTES.md) and the exact module graph before distributing a binary.
