"""Conservative NSX DFW precedence analysis for *diagnostics only*.

This builds an indicative category/policy/rule ordering from explicit sequence
numbers. It does not infer matching order across domains, scopes, implicit
rules or effective Check Point installation positions.
"""
from collections import Counter
import hashlib

DFW_CATEGORIES = ("Emergency", "Infrastructure", "Environment", "Application")
CAT_RANK = {v: i for i, v in enumerate(DFW_CATEGORIES)}


def _seq(value):
    return value if type(value) is int and value >= 0 else None


def _identity(policy, rule):
    path = rule.get("path")
    if not path:
        path = str(policy.get("path", "")) + "/" + str(rule.get("id", ""))
    return hashlib.sha256(str(path).encode()).hexdigest()[:16]


def analyze_precedence(root):
    """Return only pseudonymous rule IDs, indices, reason codes and summary.

    Source policy ordering is deterministic where all sequence numbers are
    present, unique within category and domain. Missing/tied sequences are
    never silently 'fixed' using lexical names or IDs.
    """
    from .offline import unwrap
    from .model import digest

    policies = unwrap(root)["SecurityPolicy"]
    entries = []
    issues = {}
    for pi, policy in enumerate(policies):
        category = policy.get("category")
        policy_seq = _seq(policy.get("sequence_number"))
        domain = (str(policy.get("path", "")).split("/domains/", 1)[-1]
                  .split("/", 1)[0] if "/domains/" in str(policy.get("path", ""))
                  else None)
        rules = [x["Rule"] for x in policy.get("children", [])
                 if isinstance(x, dict) and isinstance(x.get("Rule"), dict)]
        for ri, rule in enumerate(rules):
            key = _identity(policy, rule)
            codes = set()
            if category not in CAT_RANK:
                codes.add("unsupported_dfw_category")
            if policy_seq is None:
                codes.add("policy_sequence_missing")
            rule_seq = _seq(rule.get("sequence_number"))
            if rule_seq is None:
                codes.add("rule_sequence_missing")
            if domain is None:
                codes.add("domain_identity_unverified")
            if policy.get("scope") not in (None, [], ["ANY"]) or rule.get("scope") not in (None, [], ["ANY"]):
                codes.add("scoped_order_requires_path_analysis")
            if rule.get("disabled"):
                codes.add("inactive_rule_requires_default_analysis")
            if rule.get("action") in ("JUMP_TO_APPLICATION",):
                codes.add("control_flow_action_unsupported")
            if policy.get("category") == "Ethernet":
                codes.add("ethernet_l2_not_supported")
            entry = {
                "anonymous_id": key,
                "policy_index": pi,
                "rule_index": ri,
                "category": category,
                "category_rank": CAT_RANK.get(category),
                "policy_sequence": policy_seq,
                "rule_sequence": rule_seq,
                "domain": domain,
                "issues": codes,
            }
            entries.append(entry)
            issues[key] = codes

    # Detect ties, including two policies with the same category and sequence
    # and distinct policy identities. Never silently break ties by name.
    policy_keys = {}
    for pi, policy in enumerate(policies):
        cat, seq = policy.get("category"), _seq(policy.get("sequence_number"))
        domain = (str(policy.get("path", "")).split("/domains/", 1)[-1]
                  .split("/", 1)[0] if "/domains/" in str(policy.get("path", ""))
                  else None)
        if cat in CAT_RANK and seq is not None and domain is not None:
            policy_keys.setdefault((domain, cat, seq), []).append(pi)
    tied_policies = {i for ids in policy_keys.values() if len(ids) > 1 for i in ids}
    for e in entries:
        if e["policy_index"] in tied_policies:
            e["issues"].add("policy_sequence_collision")

    rule_keys = {}
    for e in entries:
        if e["rule_sequence"] is not None:
            rule_keys.setdefault((e["policy_index"], e["rule_sequence"]), []).append(e)
    for bucket in rule_keys.values():
        if len(bucket) > 1:
            for e in bucket:
                e["issues"].add("rule_sequence_collision")

    domains = set(e["domain"] for e in entries)
    if len(domains) > 1:
        for e in entries:
            e["issues"].add("cross_domain_order_not_comparable")

    # Order is a useful *diagnostic* only: unresolved entries sort after
    # explicit entries, with source encounter position as a visual fallback.
    sorted_entries = sorted(entries, key=lambda e: (
        e["category_rank"] if e["category_rank"] is not None else 99,
        e["policy_sequence"] if e["policy_sequence"] is not None else 10**18,
        e["policy_index"],
        e["rule_sequence"] if e["rule_sequence"] is not None else 10**18,
        e["rule_index"],
    ))
    output = []
    for ordinal, e in enumerate(sorted_entries, 1):
        output.append({
            "anonymous_id": e["anonymous_id"],
            "indicative_position": ordinal,
            "status": "ORDER_FIELDS_VALID" if not e["issues"] else "UNVERIFIED",
            "reasons": sorted(e["issues"]),
        })
    counts = Counter(s["status"] for s in output)
    reasons = Counter(code for row in output for code in row["reasons"])
    # This is intentionally NOT an installable policy position or a
    # declaration of semantic equivalence.
    return {
        "schema": "nxtcheckpoint.precedence-assessment.v1",
        "total": len(output),
        "order_fields_valid": counts["ORDER_FIELDS_VALID"],
        "unverified": counts["UNVERIFIED"],
        "reason_codes": dict(sorted(reasons.items())),
        "rows": output,
        "source_order_hash": digest({
            "rows": output,
            "ordering_inputs": [{
                "id": e["anonymous_id"],
                "category": e["category"],
                "policy_sequence": e["policy_sequence"],
                "rule_sequence": e["rule_sequence"],
                "policy_index": e["policy_index"],
                "rule_index": e["rule_index"],
                "domain": e["domain"],
            } for e in entries],
        }),
        "effective_enforcement_verified": False,
        "target_install_order_authorized": False,
    }
