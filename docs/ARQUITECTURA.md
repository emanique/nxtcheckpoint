# Architecture — NXTCheckpoint (read-only MVP)

## Purpose
Generic, vendor-neutral assessment orchestration between VMware NSX-T Policy API and Check Point Security Management API. The product name describes source/destination interoperability, not affiliation or vendor certification.

## Data/control planes
1. **Source collector:** queries NSX domains, policy sections, rules, groups and services using TLS-protected API requests and pagination.
2. **Compiler:** builds a canonical subset with stable source IDs and SHA-256 fingerprints; rejects risky or unsupported semantics.
3. **Delta engine:** compares to last accepted assessment, detects added/removed/modified IDs, and applies an anomaly threshold.
4. **Check Point inventory:** read-only login, access-layer inspection and paginated rulebase inspection. No target writes.
5. **Evidence and candidates:** produces JSON audit outputs; optional approval hash and topology evidence gate offline candidate creation.
6. **Scheduler:** single-host systemd oneshot every five minutes by default.

## Crucial topology constraint
NSX distributed firewall can enforce on workloads that exchange packets without any conventional gateway hop. A traditional Check Point Security Gateway only enforces traffic traversing it. No policy converter can by itself prove security equivalence. Assess packet paths, VXLAN/VLAN boundaries, routing symmetry, gateway placement, failover, HA and East-West flows separately.

## Interfaces
NSX:
- GET /policy/api/v1/infra/services
- GET /policy/api/v1/infra/domains/{domain}/groups
- GET /policy/api/v1/infra/domains/{domain}/security-policies
- GET /policy/api/v1/infra/domains/{domain}/security-policies/{policy}/rules

Check Point (read-only Management API):
- POST /web_api/login
- POST /web_api/show-access-layer
- POST /web_api/show-access-rulebase
- POST /web_api/logout

Actual supported object/schema details depend on installed releases and API versions.

## Trust and privileges
Use least-privilege API identities and valid CA bundles. Keep secrets outside source control, isolate execution host, restrict state files and avoid exposing inventory in CI. Scheduled runs must not overlap. Configure operational monitoring and backup retention externally.

## Maturity limitations
No API write, object ownership inventory, target drift reconciliation, transactional staging, policy publish/install, rollback, HA orchestration or end-to-end integration certification is present. The source read scope is not a guarantee of complete effective policy inventory. Approval string presence does not authenticate the approver.

## Target design for a future enforcement release
Introduce a separately permissioned Check Point writer restricted to a dedicated layer, external signed approvals, topology proofs, target snapshot/ownership maps, diff preview, explicit change windows, transaction commit/abort, install verification, HA-specific tests, drift reconciliation and proven rollback. **Fail closed** on incomplete source reads, incompatible semantics, target-side drift, topology bypass or missing evidence.

## Lifecycle
Observe -> Compile -> Delta -> Exceptions -> Review -> Hash-bound approval -> Offline disabled candidate -> (future staging) -> (future publish/install) -> Verification / Rollback.

See [README](../README.md), [conversion matrix](MATRIZ_CONVERSAO.csv) and [Go/No-Go](GO_NO_GO.md).
