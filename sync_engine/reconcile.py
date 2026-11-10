"""Private point-in-time group-membership reconciliation.

Never emit IPs, group paths, VM IDs or raw set differences in public reports.
Only supported, independently resolved IPv4 groups can be compared.
"""
from collections import Counter
from ipaddress import ip_address, ip_network, summarize_address_range, collapse_addresses
from .group_logic import resolve_group_expression, UnsafeExpression

class ReconciliationError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)

def _network_set(items, *, max_entries=20000):
    if not isinstance(items, list) or len(items) > max_entries:
        raise ReconciliationError("invalid_membership_list")
    nets = []
    for item in items:
        if not isinstance(item, str):
            raise ReconciliationError("invalid_member_type")
        try:
            if "-" in item:
                left, right = item.split("-", 1)
                first, last = ip_address(left.strip()), ip_address(right.strip())
                if first.version != 4 or last.version != 4 or int(first) > int(last):
                    raise ReconciliationError("invalid_ipv4_range")
                nets.extend(summarize_address_range(first, last))
            else:
                net = ip_network(item, strict=False)
                if net.version != 4:
                    raise ReconciliationError("non_ipv4_membership")
                nets.append(net)
        except (ValueError, TypeError) as exc:
            if isinstance(exc, ReconciliationError):
                raise
            raise ReconciliationError("invalid_membership_address") from None
    return tuple(collapse_addresses(nets))

def _subtract(first, second):
    """Return disjoint portions of first not present in second without expanding hosts."""
    pending = list(first)
    for exclude in second:
        new_pending = []
        for net in pending:
            if exclude.version != net.version or not net.overlaps(exclude):
                new_pending.append(net)
            elif net.subnet_of(exclude):
                continue
            elif exclude.subnet_of(net):
                new_pending.extend(net.address_exclude(exclude))
            else:
                raise ReconciliationError("invalid_network_overlap")
        pending = new_pending
    return tuple(collapse_addresses(pending))

def compare_membership(group, group_catalog, identity_map, realized):
    if realized is None:
        return {"status": "BLOCKED", "reason": "group_membership_missing"}
    try:
        if not isinstance(realized, list):
            raise ReconciliationError("invalid_membership_list")
        computed = resolve_group_expression(group, group_catalog, identity_map)
        expected = _network_set(list(computed.networks))
        actual = _network_set(realized)
        missing = _subtract(expected, actual)
        extra = _subtract(actual, expected)
    except UnsafeExpression as exc:
        return {"status": "BLOCKED", "reason": exc.code}
    except ReconciliationError as exc:
        return {"status": "BLOCKED", "reason": exc.reason}
    if missing or extra:
        return {
            "status": "MISMATCH", "reason": "effective_membership_mismatch",
            "expected_blocks": len(expected), "realized_blocks": len(actual),
            "missing_blocks": len(missing), "extra_blocks": len(extra),
        }
    return {
        "status": "MATCH", "reason": "membership_equal",
        "expected_blocks": len(expected), "realized_blocks": len(actual),
        "missing_blocks": 0, "extra_blocks": 0,
    }

def reconcile_catalog(groups, inventory):
    identity_map = inventory.get("identity_map") or {}
    realized = inventory.get("effective_group_members")
    if not isinstance(realized, dict):
        raise ReconciliationError("effective_membership_inventory_missing")
    catalog = {g["path"]: g for g in groups if g.get("path")}
    statuses = {}
    for path, group in catalog.items():
        statuses[path] = compare_membership(
            group, catalog, identity_map, realized.get(path)
        )
    return statuses

def summarize_reconciliation(statuses):
    summary = Counter(s["status"] for s in statuses.values())
    reasons = Counter(s["reason"] for s in statuses.values())
    return {
        "total": len(statuses),
        "match": summary["MATCH"],
        "mismatch": summary["MISMATCH"],
        "blocked": summary["BLOCKED"],
        "reason_codes": dict(sorted(reasons.items())),
        "go_for_conversion": bool(statuses) and summary["MISMATCH"] == 0 and summary["BLOCKED"] == 0,
        "note": "Membership match alone does not prove time consistency or gateway enforcement equivalence.",
    }
