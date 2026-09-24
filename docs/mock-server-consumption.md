# Consuming the `gvm-mock-server` GHCR Image in CI

`rust-gvm` publishes a container image for tagged releases at:

- `ghcr.io/greenbone-hive/gvm-mock-server:<v-prefixed-tag>`

Use an immutable tag shown by the repository's GitHub Releases page. At the
commit documented here, v0.7.0 is prepared but not yet tagged; do not assume its
image exists until the qualified release completes. The workflow does not
publish `latest` or an unprefixed version tag.

## Why use the image

The image gives downstream repositories a pinned mock GMP server without building Rust in every CI run. It is intended for integration tests against the standalone `gvm-mock-server` binary.

## Recommended pattern

Run the mock server over TCP inside the container and point your tests at that socket:

```bash
docker run --rm -d \
  --name gvm-mock \
  -p 127.0.0.1:9390:9390 \
  ghcr.io/greenbone-hive/gvm-mock-server:vX.Y.Z \
  --mode stateful \
  --version 22.7 \
  --tcp 0.0.0.0:9390
```

Your tests can then connect to `127.0.0.1:9390`.

## GitHub Actions example

```yaml
jobs:
  integration:
    runs-on: ubuntu-latest
    env:
      MOCK_IMAGE: ghcr.io/greenbone-hive/gvm-mock-server:vX.Y.Z
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Start mock GMP server
        run: |
          docker run --rm -d \
            --name gvm-mock \
            -p 127.0.0.1:9390:9390 \
            "$MOCK_IMAGE" \
            --mode stateful \
            --version 22.7 \
            --tcp 0.0.0.0:9390

      - name: Wait for server
        run: |
          for _ in $(seq 1 30); do
            if python3 - <<'PY'
import socket
sock = socket.create_connection(("127.0.0.1", 9390), timeout=1)
sock.close()
PY
            then
              exit 0
            fi
            sleep 1
          done
          echo "mock server did not start in time" >&2
          exit 1

      - name: Run integration tests
        env:
          GMP_HOST: 127.0.0.1
          GMP_PORT: "9390"
        run: ./scripts/test-gmp-integration

      - name: Print mock server logs on failure
        if: failure()
        run: docker logs gvm-mock
```

Replace `vX.Y.Z` and the final test command with values owned by the
downstream repository. This repository's `make test-integration` is not an
example for this container pattern: it builds and launches its own local Unix
and TLS mock servers and does not read `GMP_HOST` or `GMP_PORT`.

## Other CI systems

The same pattern works in GitLab CI, Buildkite, CircleCI, or local developer workflows:

1. Pull `ghcr.io/greenbone-hive/gvm-mock-server:<v-prefixed-tag>`.
2. Start the container with `--tcp 0.0.0.0:9390`.
3. Wait until port `9390` accepts connections.
4. Run your GMP integration tests against that address.

## Notes

- Prefer TCP in CI. Unix socket mounting is possible, but it is more runner-specific.
- The image entrypoint is `gvm-mock-server`, so pass normal CLI flags after the image name.
- Release tags are the compatibility boundary. Upgrade by changing the image tag in your CI config.
- The release image is built with the mock server's default features. Its CLI
  exposes Unix sockets and TCP, not the feature-gated TLS or library-only SSH
  listeners. TCP is the intended container integration path.
- Stateful TLS-certificate commands use a bounded set of registered PEM/DER
  fixtures. They model ownership, fingerprints, lifecycle operations, query
  expansions, and permanent deletion, but are not a general X.509 parser,
  cryptographic verifier, ACL/filter engine, or live-gvmd conformance suite.
  Unregistered certificate payloads are deliberately rejected; see the
  [TLS evidence and limitations](tls-certificate-request-gvmd-evidence.md).
- Stateful NVT/SecInfo discovery uses deterministic textual OIDs, configuration
  membership and preference overlays, SecInfo entries, observed vulnerability
  summaries, saved filters, and explicit availability/permission toggles. The
  five discovery roots are immutable queries with a bounded filter language;
  the mock is not a feed parser, SQL emulator, complete ACL implementation, or
  real-gvmd conformance suite. Fixture mode shares supported-type validation
  and authoritative response shapes. See the
  [NVT/SecInfo evidence and limitations](nvt-secinfo-request-gvmd-evidence.md).
- Stateful configuration lifecycle behavior uses shared seeded generic,
  scan-config, and policy resources. It models required copy/import creation,
  bounded selectors/preferences, configured preference updates, ordered
  NVT/family replacement, literal filters/counts, atomic metadata/mutation
  rollback, task-sensitive trash deletion, and explicit `sync_config`
  rejection. It does not model rich trash expansion, a complete
  filter/ACL/feed engine, internal SQL cleanup, or unseeded NVT reconciliation.
  See the
  [configuration evidence and limitations](scan-config-policy-request-gvmd-evidence.md).
