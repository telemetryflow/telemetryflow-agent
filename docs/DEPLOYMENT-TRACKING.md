# Deployment Tracking (`tfo-agent deploy`)

> Report software deployments to the TelemetryFlow platform (**Operations →
> Deployments**) directly from the agent — no separate CLI. Available since
> **v1.3.7**.

The agent already forwards **errors** to the platform as OTLP (span `exception`
events + ERROR logs → TFO-Sentry); this page covers the complementary
**deployment** signal: a `tfo-agent deploy` command that records *when / where /
by-whom* a version shipped, so a deploy becomes a first-class, queryable event
you can overlay on telemetry and correlate with error-tracking releases.

## Why the agent (not a separate CLI)

The platform's deploy-ingest endpoint (`POST /api/v2/deployments`) is
transport-agnostic and authenticates with the **same ingestion key** the agent
already uses for telemetry. So any pipeline that runs `tfo-agent` can report a
deploy with one command — no extra binary, no second credential. The REST
endpoint remains available for pipelines that don't run the agent.

## Quick start

```bash
tfo-agent deploy \
  --service checkout \
  --version 1.3.7 \
  --status success \
  --provider github \
  --commit "$GITHUB_SHA" \
  --ref main
```

Output:

```
Deployment recorded: id=4f3c… status=success created=true
```

The tenant and project are resolved **server-side** from the ingestion key — you
never pass them on the command line.

## Authentication & endpoint

`deploy` reuses the agent's TelemetryFlow credentials. It resolves, in order:

1. **Flags** — `--endpoint`, `--key-id`, `--key-secret` (highest priority).
2. **Agent config** — when a flag is omitted, it falls back to the loaded
   config: `telemetryflow.backend_endpoint` (or `endpoint`) and
   `api_key_id` / `api_key_secret` (the `tfk_…` / `tfs_…` ingestion key).

The request is sent as `POST {endpoint}/api/v2/deployments` with headers
`X-TelemetryFlow-Key-ID` / `X-TelemetryFlow-Key-Secret`.

| Flag | Default | Purpose |
|------|---------|---------|
| `--service` | — (**required**) | Service name; correlates to telemetry `service.name` |
| `--version` | — (**required**) | Deployed version (`service.version`) — the correlation key |
| `--status` | `success` | `queued \| running \| success \| failed \| rolled_back` |
| `--provider` | `cli` | `github \| gitlab \| bitbucket \| jenkins \| aws \| azure \| argocd \| cli` |
| `--external-id` | generated | Provider run/deployment id (dedup key) |
| `--environment` | `production` | Target environment |
| `--commit` / `--ref` | — | Commit SHA / branch (suspect-commit attribution) |
| `--actor` | — | Who triggered it (**hashed server-side** before storage) |
| `--url` | — | Link to the pipeline run (display only, never fetched) |
| `--started-at` / `--finished-at` | — | ISO 8601 timings (lead-time / MTTR) |
| `--endpoint` / `--key-id` / `--key-secret` | agent config | Override auth/endpoint |
| `--insecure` | `false` | Skip TLS verification (self-signed platform certs) |

Validation happens client-side: a missing `--service`/`--version` or an invalid
`--status`/`--provider` fails fast, before any request.

## Status lifecycle

A deployment may be **created** at any status (a one-shot `--status success` is
common). Repeat calls with the **same `--external-id`** update the same
deployment (idempotent); a status change follows the platform state-machine
(`queued → running → success | failed | rolled_back`, plus rollback/retry edges).

## CI/CD examples

**GitHub Actions**

```yaml
- name: Report deployment
  run: |
    tfo-agent deploy --service checkout --version "${{ github.ref_name }}" \
      --status success --provider github \
      --commit "${{ github.sha }}" --ref "${{ github.ref_name }}" \
      --external-id "${{ github.run_id }}" \
      --url "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
```

**GitLab CI**

```yaml
report_deploy:
  script:
    - tfo-agent deploy --service checkout --version "$CI_COMMIT_TAG" --status success
      --provider gitlab --commit "$CI_COMMIT_SHA" --ref "$CI_COMMIT_REF_NAME"
      --external-id "$CI_PIPELINE_ID" --url "$CI_PIPELINE_URL"
```

**Jenkins / generic shell**

```bash
tfo-agent deploy --service worker --version "$BUILD_VERSION" --status "$RESULT" \
  --provider jenkins --external-id "$BUILD_TAG" --url "$BUILD_URL"
```

Report the start and the end for lead-time/MTTR:

```bash
tfo-agent deploy --service api --version 1.3.7 --status running   --external-id "$RUN_ID"
# … deploy …
tfo-agent deploy --service api --version 1.3.7 --status success   --external-id "$RUN_ID"
```

## Configuration

See [`configs/examples/deployment.yaml`](../configs/examples/deployment.yaml) for
a minimal config that supplies the endpoint + ingestion key so pipelines can call
`tfo-agent deploy` with just `--service/--version/--status`. Any field can still
be overridden per-invocation with a flag.

## How it fits end-to-end

```mermaid
flowchart LR
  CI[CI/CD pipeline] -->|tfo-agent deploy| API["/api/v2/deployments"]
  API --> PG[(deployments · PostgreSQL)]
  API --> CH[(deployment_events · ClickHouse)]
  API -. deployments.* .-> ERR[Error Tracking: release correlation]
  PG --> UI[Operations → Deployments UI + chart markers]
  CH --> UI
```

A successful deploy publishes `deployments.succeeded`, which Error Tracking uses
to stamp the matching release and attribute post-deploy regressions to that
deploy (shared `service` + `version`).

## See also

- [COMMANDS.md](./COMMANDS.md) — all `tfo-agent` subcommands.
- [TFO-PLATFORM-INTEGRATION.md](./TFO-PLATFORM-INTEGRATION.md) — ingestion keys,
  endpoint, and error (OTLP) forwarding.
- Platform guide: `docs/getting-started/tfo-sentry-end-to-end-guide.md` (Error
  Tracking) and `docs/modules/deployment-tracking-roadmap.md` (Deployment
  Tracking) in the monolith.
