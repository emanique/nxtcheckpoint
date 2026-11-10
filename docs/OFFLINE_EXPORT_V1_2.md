# NXTCheckpoint v1.2 — offline hierarchical export support

The v1.2 offline importer is built to handle NSX **Infra** JSON exports. It was designed against the *structure* of a complex, privately inspected export; the original export, its network addresses, workload names, rule names and full configuration are **not** included in this public repository.

## Supported input

- Top-level `resource_type: Infra` JSON file with `children`
- UTF-8 (with or without BOM) and UTF-16 BOM
- Nested `ChildDomain`, `ChildSecurityPolicy`, `ChildRule`, `ChildGroup`, `ChildService` wrappers
- Policy, rule, group and service inventory
- Simple IPv4 groups based on one `IPAddressExpression`
- TCP/UDP L4 services without source-port restrictions
- Blocking classifications for complex groups, source-port constraints, unsupported services, explicit DFW scope, dual-stack, security profiles, statefulness differences, ANY, missing references and other potentially unsafe features

**Do not collapse** expressions such as `ExternalIDExpression AND IPAddressExpression` to a union of IPs. They are blocked until expression semantics and workload membership can be reproduced correctly.

## Usage

```bash
python3 -m sync_engine.offline \
  --input /secure/private/nsx-infra-export.json \
  --output /secure/private/assessment
```

The output directory contains:
- `summary.json`: object counts, classification counts, reason code frequency, no original names/IPs
- `rules.csv`: derived 16-character SHA-256 source-reference fingerprints, classification and reason codes

**Privacy note:** fingerprints are **pseudonymous**, not cryptographically anonymous against guessing known source paths. Do not upload output reports to public repositories. The tool does not write raw source data to the output files, but raw input remains sensitive.

## Compatibility classification

- **A**: syntactically translatable *object* (simple static IPv4 group or TCP/UDP service) — not yet eligible for enforcement without external validation.
- **B**: rule with no detected syntactic blockers, but which still requires proof of topology, placement, precedence and runtime behaviour.
- **C**: rule with at least one identified blocker or unsupported semantic; excluded from automatic conversion.

A source may contain zero B rules even when many reusable groups/services are class A. This is expected in strict fail-closed mode.

## Boundaries

The initial v1.2 delivers **offline assessment, not a Check Point writer**. It does not attempt to validate target routing, simulate enforcement, query virtual machine IPs, fully interpret dynamic group expressions or analyze shadowing/precedence. Do not feed outputs directly to Check Point API.

The existing periodic NSX Policy API collector is separate; offline import does not yet populate its `latest_plan.json` or `latest_snapshot.json`. Treat the two workflows as independent until a tested normalized model merges them.

## Local verification

```bash
python3 -m pytest -q tests/test_offline.py
```

Only synthetic test fixtures are allowed in the repository. Never commit actual exports, inventory snapshots, real names/IPs, original paths, raw identifiers or output assessment reports.

See [README](../README.md), [conversion matrix](MATRIZ_CONVERSAO.csv), and [semantic conversion specification](AUTOMATIZACAO_CONVERSAO.md).
