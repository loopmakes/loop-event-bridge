# Container releases

GitHub Actions builds the image on standard `ubuntu-24.04` GitHub-hosted runners. This repository is public: standard Actions runners are free for public repositories, and public GHCR packages are free. No paid runner, external build service, or personal registry token is required. Check [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions) and [Packages billing](https://docs.github.com/en/billing/concepts/product-billing/github-packages) if these policies change.

The `Container image` workflow runs Go tests, race detection, vet, a static build, an offline container smoke test, and browser security regressions before building `linux/amd64` and `linux/arm64` images. Main-branch pushes and pull requests only validate the build. A `vMAJOR.MINOR.PATCH` Git tag additionally publishes these tags:

- `ghcr.io/loopmakes/loop-event-bridge:MAJOR.MINOR.PATCH`
- `ghcr.io/loopmakes/loop-event-bridge:vMAJOR.MINOR.PATCH`

Only the publishing job receives `packages: write`, using GitHub's short-lived `GITHUB_TOKEN`. No repository secret or personal token needs to be added. OCI labels record the source repository, MIT license, release version, and source commit; build arguments embed the version/revision in startup logs. The build uses a minimal allowlisted Docker context; deployment configuration, secrets, and state are excluded.

## Publish a version

1. Land the intended source and workflow changes on `main`; wait for both CI and the multi-architecture build to pass for that exact commit.
2. Confirm the version tag does not already exist. Create an annotated version tag on that tested commit and push that tag. Never move an existing release tag or replace an already published release with different source.
3. Wait for `Container image`. Its summary provides the immutable manifest-list digest.
4. For the **first publication only**, GitHub may create the package as private. The repository owner must open the package settings and change this specific container package to public. Then rerun only the failed `verify-public` job. Linking a public repository alone does not make a package public.
5. Require `verify-public` to pass before announcing availability. This fresh job has no permissions or registry credentials; it checks both platform manifests, pulls the version tags anonymously, and verifies the expected digest and OCI version/revision labels.

Use `ghcr.io/loopmakes/loop-event-bridge@sha256:...` from the verified run summary for an immutable deployment. The workflow does not access or deploy to any Swarm, create a GitHub Release, or change existing servers.
