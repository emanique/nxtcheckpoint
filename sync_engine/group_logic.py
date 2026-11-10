"""Conservative group-expression compiler.

Internal results can contain confidential IPs and identity references.
Never write the AST or resolved addresses to public reports.
"""
import ipaddress
from dataclasses import dataclass


class UnsafeExpression(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Resolution:
    networks: tuple
    identity_dependencies: tuple
    group_dependencies: tuple
    complete: bool


def _networks(values):
    out = []
    for raw in values:
        try:
            text = str(raw)
            if '-' in text:
                raise UnsafeExpression("ip_range_requires_expansion")
            net = ipaddress.ip_network(text, strict=False)
            if net.version != 4:
                raise UnsafeExpression("non_ipv4_address")
            out.append(net)
        except (TypeError, ValueError) as exc:
            if isinstance(exc, UnsafeExpression):
                raise
            raise UnsafeExpression("invalid_ip_network") from exc
    return tuple(ipaddress.collapse_addresses(out))


def _intersection(left, right):
    overlaps = []
    for a in left:
        for b in right:
            if a.subnet_of(b):
                overlaps.append(a)
            elif b.subnet_of(a):
                overlaps.append(b)
    return tuple(ipaddress.collapse_addresses(overlaps))


def _union(left, right):
    return tuple(ipaddress.collapse_addresses((*left, *right)))


def resolve_group_expression(group, groups=None, identity_map=None, _seen=None):
    """Resolve IPv4-only IP, ExternalID, Path and AND/OR expressions.

    identity_map maps a workload ID to current verified IPv4 host addresses.
    Without it, ExternalID cannot be safely converted.
    PathExpression requires referenced group objects supplied by path.
    Empty intersections are valid but must be held for review, not turned into ANY.
    """
    groups = groups or {}
    identity_map = identity_map or {}
    seen = set(_seen or ())
    path = group.get("path")
    if path:
        if path in seen:
            raise UnsafeExpression("recursive_group_cycle")
        seen.add(path)
    if group.get("extended_expression"):
        raise UnsafeExpression("unsupported_extended_expression")
    expr = group.get("expression") or []
    if not expr or len(expr) % 2 == 0:
        raise UnsafeExpression("empty_or_invalid_expression")
    values = []
    operators = []
    identities = set()
    dependencies = set()
    for index, token in enumerate(expr):
        kind = token.get("resource_type")
        if index % 2:
            if kind != "ConjunctionOperator":
                raise UnsafeExpression("missing_boolean_operator")
            op = token.get("conjunction_operator")
            if op not in ("AND", "OR"):
                raise UnsafeExpression("unsupported_boolean_operator")
            operators.append(op)
            continue
        if kind == "IPAddressExpression":
            addresses = token.get("ip_addresses") or []
            if not addresses:
                raise UnsafeExpression("empty_ip_expression")
            values.append(_networks(addresses))
        elif kind == "ExternalIDExpression":
            if token.get("member_type") != "VirtualMachine":
                raise UnsafeExpression("unsupported_identity_type")
            ids = token.get("external_ids") or []
            if not ids:
                raise UnsafeExpression("empty_identity_expression")
            addresses = []
            for ident in ids:
                identities.add(str(ident))
                if ident not in identity_map:
                    raise UnsafeExpression("unresolved_workload_identity")
                mapped = identity_map[ident]
                if not isinstance(mapped, list) or not mapped:
                    raise UnsafeExpression("unverified_workload_membership")
                addresses.extend(mapped)
            values.append(_networks(addresses))
        elif kind == "PathExpression":
            paths = token.get("paths") or []
            if not paths:
                raise UnsafeExpression("empty_path_expression")
            resolved = []
            for ref in paths:
                dependencies.add(str(ref))
                target = groups.get(ref)
                if target is None:
                    raise UnsafeExpression("unresolved_group_path")
                nested = resolve_group_expression(target, groups, identity_map, seen)
                identities.update(nested.identity_dependencies)
                dependencies.update(nested.group_dependencies)
                resolved.extend(nested.networks)
            values.append(_networks(resolved) if resolved else ())
        else:
            raise UnsafeExpression("unsupported_group_expression_type")
    # NSX expressions combining AND/OR must not be reinterpreted with guessed
    # precedence. Only homogeneous operator sequences are evaluated.
    if len(set(operators)) > 1:
        raise UnsafeExpression("mixed_boolean_precedence_unverified")
    result = values[0]
    for op, value in zip(operators, values[1:]):
        result = _intersection(result, value) if op == "AND" else _union(result, value)
    if not result:
        raise UnsafeExpression("empty_resolved_intersection")
    return Resolution(
        networks=tuple(str(n) for n in result),
        identity_dependencies=tuple(sorted(identities)),
        group_dependencies=tuple(sorted(dependencies)),
        complete=True,
    )
