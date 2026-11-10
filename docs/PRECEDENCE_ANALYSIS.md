# NSX-T DFW precedence assessment — diagnostic only

NXTCheckpoint can now assess **ordering metadata** in private NSX Infra exports, without translating the order into executable Check Point Access Layer positions.

## Confirmed source ordering model

NSX DFW categories are processed by category priority (for supported L3 rules: **Emergency → Infrastructure → Environment → Application**); rules in the relevant category and policy are evaluated in order. See the Broadcom [SecurityPolicy API schema](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/types_SecurityPolicy.html) and [official DFW policy sequencing advisory](https://knowledge.broadcom.com/external/article/416685/distributed-firewall-dfw-policy-sequenci.html).

The compiler considers `category`, `sequence_number` at both policy and rule levels, explicit source order, scope, disabled rules and domain identity. It does **not** assume lexical names or IDs imply sequence.

## Diagnostic results

| Result | Meaning |
|---|---|
| `ORDER_FIELDS_VALID` | Category, source domain, policy sequence and rule sequence are present, unambiguous among the inspected entries |
| `UNVERIFIED` | Missing/ambiguous sequencing, unsupported category, multi-domain order, explicit scope or other unsupported control-flow semantics |
| `source_order_hash` | SHA-256 fingerprint bound to category, input positions, both sequence fields and diagnostic output; prevents silent approval reuse after reordering |
| `effective_enforcement_verified=false` | Always false: no packet/first-match or cleanup-rule verification |
| `target_install_order_authorized=false` | Always false: no target policy insert coordinates are generated |

`ORDER_FIELDS_VALID` is deliberately **not** evidence that the target Security Gateway can enforce the same behavior. Policy-specific Applied-To, distributed East-West traffic, default rules, traffic statefulness, and existing Check Point rulebase overlap still need independent validation.

## Fail-closed checks and diagnostics

- Unrecognised category or L2/Ethernet/IDPS-specific ordering
- Missing, negative or non-integer policy/rule sequence
- Colliding policy sequences in the same domain/category
- Colliding rule sequences within a policy
- Cross-domain ordering without a validated domain-mapping model
- Applied-To scope that needs a traffic-path proof
- Disabled rule, jump/control-flow action and implicit cleanup limitations

The diagnostics contain only **pseudonymous rule identifiers** and reason codes; real rules/IPs remain in local private inputs.

## Integration

`sync_engine.offline.assess` adds a sanitized `precedence` section to `summary.json`. `sync_engine.approval_template` writes a blank private review worksheet containing `source_order_hash`. The `sync_engine.canonical_bridge` checks this value before generating each disabled candidate and preserves the indicative source position for review.

The ordering fingerprint tracks changes in the inspected source even if the same rule action, group membership and service definitions remain unchanged. This avoids accidentally reusing a previous approval after resequencing.

### Use

```bash
python -m sync_engine.approval_template \
  --input /secure/private/nsx-export.json \
  --inventory-file /secure/private/inventory/inventory.private.json \
  --output /secure/private/approvals.json
```

Approval fields start blank. An external authorized reviewer must provide real topology and precedence evidence before any candidate can be generated.

```bash
python -m sync_engine.canonical_bridge \
  --input /secure/private/nsx-export.json \
  --inventory-file /secure/private/inventory/inventory.private.json \
  --approvals /secure/private/approvals.json \
  --output /secure/private/canonical
```

**The Check Point object dry-run does not install rules**; it consumes candidate objects only. The candidate's rule sequence is for human diagnostic review, not an API `position` value.

## Key limitations

- No guarantees of a single atomic NSX source snapshot or complete effective DFW inventory.
- No fully modelled implicit defaults, `JUMP_TO_APPLICATION`, layer attachment, identity firewall or multi-domain rule ordering.
- No rule shadowing or overlap proof with pre-existing Check Point rules.
- No target gateway topology, HA enforcement, publish/install or rollback execution.
- **No production Go** can be based on the diagnostic order, even if every entry is `ORDER_FIELDS_VALID`.

All public tests use synthetic inputs only.
