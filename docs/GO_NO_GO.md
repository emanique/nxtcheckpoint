# Go / No-Go assessment and future enforcement controls

**Current project capability:** source assessment and offline candidate generation only. The following gates must be met before *future* policy enforcement features may be enabled. This checklist is not proof of compliance or approval.

| Gate | Criterion | No-Go if |
|---|---|---|
| G01 | Valid source inventory, domains and API pagination | Missing policy/objects or collection errors |
| G02 | Source rules and groups have stable identity and mapping | Dangling references or dynamic unsupported semantics |
| G03 | Routing and topology verified per protected flow | Traffic may bypass Check Point gateway |
| G04 | DFW rule precedence and target order equivalence proven | Shadowing/default-policy differences |
| G05 | Both allowed and denied flows tested | Unexplained connectivity or exposure |
| G06 | Target object ownership and collision plan | Conflicts with existing managed objects |
| G07 | Change authorization tied to candidate hash | Approval missing, stale or unverifiable |
| G08 | Target snapshot and recoverable backups | No validated restoration point |
| G09 | Operational change window and rollback owner | No reversible execution plan |
| G10 | Check Point API/rulebase integration tests | API version ambiguity or authentication errors |
| G11 | HA/cluster failover and policy install verification | Members inconsistent or untested |
| G12 | Monitoring and audit retention | Missing telemetry or unable to reconstruct changes |

## Decision rules
- **GO for assessment:** source API permissions, CA trust, storage protection and repeatable read-only operation are verified.
- **GO for offline candidate:** supported semantics and per-rule hash-bound evidence are present, with exceptions explicitly reviewed.
- **NO-GO for enforcement in MVP:** writes, publication, installation, rollback and live drift protection are **not implemented**.
- Never use a successfully generated JSON file as evidence that effective firewall protection is equivalent.

## Evidence to archive
Source snapshot/version, canonical hashes, changed/removed rule list, exceptions, source and target versions, routing tests, explicit approval, test results, target backup, execution log, and validated rollback result. Keep these artifacts restricted and outside public repositories.
