# Semantic rule conversion — NSX-T DFW to Check Point Security Gateway

This document specifies the architecture for **future** translation. The current project collects source configuration and produces offline disabled candidates. It **does not** write to Check Point Management API.

## Severity model

- **A: direct syntax mapping**. The normalized object can be created deterministically, but topology tests still gate enforcement.
- **B: conditional**. Must satisfy additional semantic checks (including scope, path, time, direction, ordering, dynamic membership).
- **C: blocked**. No verified equivalence; manual redesign or separate implementation needed.

See [compatibility matrix](MATRIZ_CONVERSAO.csv).

## Compiler pipeline

1. **Discover:** retrieve DFW policies, rule sections, groups, services, realized membership, schedule and defaults with pagination, revision and source domain identity. A fully effective snapshot may require more endpoints than the current MVP uses.
2. **Normalize:** build CanonicalPolicy objects with unique `source_id`, `revision`, canonical source/destination sets, service sets, action, direction, negations, schedule, scope, statefulness, logging, category, policy sequence and rule sequence.
3. **Resolve:** recursively expand nested/static groups with cycle detection, keep reference ownership, and validate VM identity mappings. Preserve immutable identifiers and hash content.
4. **Classify:** run compatibility validators. Unsupported fields must **reject**, never disappear silently.
5. **Topology:** map each flow to a target security gateway, check symmetric return path, routing, NAT and intra-segment bypass. No topology proof means candidate cannot be enabled.
6. **Analyze rulebase:** preserve category/section precedence, explicit and implicit defaults, shadowing, overlaps, first-match behavior, disabled rules, and existing target rulebase interactions.
7. **Stage (future):** generate named target objects and **disabled** rules in a dedicated layer, using idempotent ownership references. All writes must stay in a separate approval-scoped Check Point session.
8. **Verify:** compare generated rules and objects to expected normalized state; produce diff and evidence. Publish/install only after independent approval and successful tests.
9. **Reconcile:** periodically detect source deltas and target drift. Do not auto-remove or auto-enable rules just because a source object disappeared.

## Canonical schema example

```json
{
  "source_id": "domain/policy/rule",
  "source_revision": 12,
  "category": "Application",
  "policy_order": 200,
  "rule_order": 30,
  "source": [{"type":"network","cidr":"10.20.1.0/24"}],
  "destination": [{"type":"host","ip":"10.20.2.10"}],
  "service": [{"protocol":"TCP","destination_ports":["443"]}],
  "action": "ALLOW",
  "direction": "IN_OUT",
  "source_negate": false,
  "destination_negate": false,
  "scope": [],
  "stateful": true,
  "tcp_strict": null,
  "time": null,
  "enabled": true,
  "log": true,
  "topology_proof": null,
  "classification": "B",
  "blocking_reasons": ["Gateway packet-path proof required"]
}
```

This is the **target schema**, not a currently supported wire format.

## API object plan (future write stage)

```text
Check Point Management API:
  login (write session)
  show-* (read target inventory and revisions)
  add-host / add-network / add-address-range / add-group / add-service-tcp / add-service-udp
  add-access-rule (disabled, chosen layer, explicit position, namespaced ownership)
  show-access-rulebase (post-staging verification)
  publish OR discard (explicit change decision)
  install-policy (separate approved change step)
  show-task / verify gateway and HA members
```

Do not blindly create duplicate objects or update user-owned rules. Establish source-to-target IDs in a protected mapping database. Consider partial success, concurrent editors, API retries and reconciliation after failed sessions.

## Continuous sync state machine

```text
SOURCE_CHANGE
   -> INVENTORY_VERIFIED
   -> SEMANTIC_CLASSIFIED
   -> TOPOLOGY_VERIFIED
   -> DIFF_APPROVED
   -> STAGED_DISABLED (future)
   -> STAGE_VERIFIED (future)
   -> PUBLISH_APPROVED (future)
   -> PUBLISHED (future)
   -> INSTALL_APPROVED (future)
   -> INSTALLED_AND_VERIFIED (future)
   -> CLOSED
```

Any mismatched hash, missing rule, failed authentication, unsupported attribute, target drift, altered ordering or exceeded change threshold must transition to **BLOCKED**. Existing checkpoint policy must remain untouched.

## Concrete examples

| NSX definition | Target | Conclusion |
|---|---|---|
| src 10.20.1.0/24; dst 10.20.2.10; TCP/443; ALLOW | Network + Host + TCP service + Accept | Syntax A, enforcement B until path validated |
| src dynamic tag APP=FRONTEND; dst static subnet; UDP/53 | Dynamic/member-sync + UDP service | B, requires membership reconciliation |
| scope=AppVMs; action DROP | Drop with gateway placement | B/C depending on dataplane coverage |
| direction=IN or OUT, same subnet | No assured gateway enforcement | Block until topology redesigned |
| L2 Ethernet drop | No general gateway equivalent | C |
| `JUMP_TO_APPLICATION` | Requires policy control-flow modelling | C |

## Security tests required for release

1. A/B/C fixtures and boundary testing, including IPv6, ranges, source ports, ICMP and empty/ANY operands.
2. Negated groups and nested groups are either semantically preserved or rejected.
3. Cross-domain, policy categories, rule order, disabled rules and implicit cleanup are evaluated.
4. Source and destination scope and IN/OUT behavior have packet-path evidence.
5. Changed or removed objects cannot silently widen access.
6. Target-side drift or rule shadowing blocks approval.
7. Retry/restart/partial API writes do not create duplicates.
8. Session discard, publish, install task, HA and rollback are tested against supported product versions.
9. Positive and negative traffic are both verified, with post-install logging.
10. No change is considered production-ready on the basis of syntax conversion alone.

## Scope and reality check

The initial read-only compiler does not yet resolve direct IPv4 operands, nested/dynamic membership, implicit rules, schedules, special protocol profiles, or multi-domain effective order. Those must be added before claiming broad automated conversion coverage. A conventional Security Gateway does not inherit DFW enforcement placement.
