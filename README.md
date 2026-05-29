# reach-testbed-go

Intentionally vulnerable Go fixture repository for exercising REACHABLE signal
families against a compact `net/http` service.

> Do not deploy this application. It contains synthetic security issues for
> scanner validation only.

## Implementation Plan

1. Keep the fixture Go-centric and dependency-light: one `cmd/server` entrypoint
   with handlers in `internal/handlers`.
2. Model one reachable case for each major signal family:
   CVE, CWE, secret, config, DLP, AI/LLM misuse, malware/suspicious behavior.
3. Include comparison cases for `UNKNOWN` / assess, defended findings, and a
   no-fix CVE with a documented compensating control.
4. Track dependency-upgrade expectations in `go.mod`, `go.sum`, and the
   customer-facing baseline manifest in `EXPECTED.md` so scanner regressions
   can be diffed without guessing.
5. Keep all secrets and DLP data synthetic.

## Layout

```text
cmd/server/              HTTP entrypoint and route registration
internal/handlers/       Reachable, defended, and assess signal cases
internal/safety/         Small guard helpers used by defended cases
config/                  Synthetic insecure configuration cases
deploy/                  Synthetic IaC cases for config scanners
testdata/dlp/            Synthetic DLP corpus
EXPECTED.md              Customer-facing baseline manifest of expected findings
```

## Local Smoke Test

```bash
go test ./...
go run ./cmd/server
```

The service listens on `:8080` by default.
