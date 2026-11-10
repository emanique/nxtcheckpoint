# Check Point object dry-run (experimental)

The current NXTCheckpoint release has a **read-only object planning** feature. It does not create, update, delete, publish or install Check Point objects or policies. It is a foundation for a future controlled staging writer, not a ready-to-run policy migration.

## Input contracts

- A **private** `latest_candidate.json` produced by the online candidate exporter (`python -m sync_engine.candidate`).
- A complete target object inventory from one of:
  - A private JSON snapshot with five keys (`host`, `network`, `group`, `service-tcp`, `service-udp`), each containing a full list.
  - The existing read-only Check Point Management API connection, which fetches all five object kinds using `show-hosts`, `show-networks`, `show-groups`, `show-services-tcp`, `show-services-udp` with pagination.
- Candidate hash validation matches the producer's payload hashing scheme. **Rejected source rules block planning**; repair or segregate rejected rules before using the plan. This is a strict default.

This feature is **not yet connected** to the separate hierarchical NSX export/reconciliation pipeline. A synchronized canonical policy model remains future work.

## Run with a private target snapshot

```bash
python -m sync_engine.object_plan \
  --candidate /secure/private/latest_candidate.json \
  --target-snapshot /secure/private/checkpoint-objects.json \
  --output /secure/private/dry-run-001
```

The JSON object snapshot must contain **all five** keys, not merely objects that appear to match candidates. The supplied snapshot's completeness and freshness are operator responsibilities.

## Run against live Check Point — read only

```bash
export CP_API_KEY="read-only-api-key"
python -m sync_engine.object_plan \
  --candidate /secure/private/latest_candidate.json \
  --config /etc/nsxcp/config.yaml \
  --output /secure/private/dry-run-002
```

The Management API client logs in with `read-only: true`, uses only `show-*` endpoints and logs out. No `add-*`, `set-*`, `publish`, `install-policy` or delete request is made.

## Outcomes

| Action | Meaning |
|---|---|
| `CREATE` | No existing target object has this name; *proposed* object payload, not submitted |
| `REUSE` | Same name, type, explicit ownership marker and normalized semantics |
| `CONFLICT` | Existing type, ownership, fields or name allocation is incompatible |
| `ready_for_review` | No object conflicts detected — **not approval** to publish or install |

Host IPv4, network prefix, group member name sets, and TCP/UDP ports are checked. New groups are processed after their member objects. The generator requires all names in the owned `NSXMIG_` namespace and tags proposed objects using a deterministic `NXTCP:` marker derived from the private source reference.

**Ownership is not cryptographic identity.** A future writer needs durable source/target UID mapping, transaction protections, object-level change ownership, concurrency control and independently authenticated change approvals.

## Privacy and output

The detailed output `object_plan.private.json` includes object names, IPs, services and source-derived hashes. It is written with restricted permissions to a private directory; never publish it, attach it to a public issue or upload it as a CI artifact.

CLI output is limited to action counts, a plan hash and a read-only indicator. GitHub tests use synthetic object names and RFC 5737 documentation-only IP ranges.

## Non-goals and limitations

- No Check Point writes, rulebase/ordering conversion, policy installation, rollback or topology equivalence.
- Does not deduce ownership from name alone. Matching semantics under another owner are a conflict.
- Does not prove completeness/freshness of snapshots, detect concurrent Check Point changes or compare Check Point object UIDs.
- No enforcement of the future policy position, implicit rules, network path or HA membership.
- The original hierarchical export and sensitive input data remain local/private.

## Verification

```bash
pytest -q tests/test_object_plan.py
pytest -q
```

Further development must implement a transactional staging adapter behind an explicit approval and Go/No-Go gate; the dry-run results are intended for human review only.
