# Effective NSX group-membership reconciliation

The read-only NXTCheckpoint reconciler checks **effective IP membership** returned by NSX against **IPv4 membership computed** from supported source group expressions. It is intended to detect semantic drift before translating groups into Check Point objects.

## Mechanics

1. Collect the source policy, source group definitions, VM IDs and VIF addresses via read-only NSX APIs.
2. Load a private, freshness-checked inventory (`sync_engine.inventory`).
3. Evaluate the original group expression with `sync_engine.group_logic` (unsupported semantics fail closed).
4. Normalize effective NSX group members into IPv4 sets, supporting host addresses, CIDR networks and inclusive address ranges.
5. Compare both sets using subnet algebra: `expected - realized` and `realized - expected`. No host-by-host expansion.
6. Return `MATCH`, `MISMATCH`, or `BLOCKED`, with non-sensitive reason codes and block counts.
7. Block offline rule candidacy whenever a referenced group is not `MATCH`.

A `MATCH` is evidence of equality **for two collected snapshots**, not necessarily of a consistent instant in time. Without coordinated snapshot controls, dynamic changes between reads may produce a valid but stale comparison.

## CLI

```bash
python -m sync_engine.inventory \
  --config /etc/nsxcp/config.yaml \
  --output /secure/private/inventory-run-001

python -m sync_engine.offline \
  --input /secure/private/nsx-export.json \
  --inventory-file /secure/private/inventory-run-001/inventory.private.json \
  --max-inventory-age-seconds 600 \
  --output /secure/private/assessment-run-001
```

The `summary.json` includes a `reconciliation` object. Only aggregate counts and reason codes are output. The `rules.csv` contains pseudonymized rule IDs and a `group_membership_not_verified` reason whenever relevant. Neither raw IPs, VM IDs nor group paths are included in reports.

## Guard conditions

- Missing or invalid effective members: **BLOCKED**.
- Unsupported expression, identity, IPv6 or invalid addresses: **BLOCKED**.
- Computed and effective membership are different: **MISMATCH**, with difference counts.
- Complete equality: **MATCH** — subject to topology, precedence, routing and freshness checks.
- No private inventory: **NOT_PERFORMED**; never interpreted as equality.

## Known gaps

- The current offline path does not independently prove that the export and live NSX inventory represent one atomic snapshot.
- A Check Point Security Gateway can only enforce flows that traverse it; membership equality alone is not a topology proof.
- The API group-members endpoint and VIF fields must be validated against the deployment's actual NSX version.
- The pipeline does not create target objects or rules, or publish/install a policy.
- Comparisons are IPv4-only; unsupported or complex NSX expressions remain rejected.
- Saltless pseudonymous IDs in pre-existing reports can be correlatable to known source paths. Keep reports private.
- The offline converter and periodic online collector are still separate paths.

## Verification

```bash
pytest -q tests/test_reconcile.py
pytest -q
```

All committed tests use synthetic objects and documentation-only addresses. Keep original exports, identity maps, inventory snapshots, topology traces and assessment output in a restricted private directory, never in the public repository.
