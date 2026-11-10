"""Private hash of complete rule dependencies for approvals.

Changing a referenced group's resolved IP membership or service definition
invalidates approvals even when the source rule JSON itself is unchanged.
"""
from .group_logic import resolve_group_expression, UnsafeExpression
from .model import digest
from .offline import unwrap


class DependencyHashError(ValueError):
    pass


def semantic_rule_hash(rule, group_catalog, service_catalog, identity_map):
    dependencies = {"rule": rule, "groups": {}, "services": {}}
    for field in ("source_groups", "destination_groups"):
        for path in rule.get(field, []):
            if path == "ANY":
                raise DependencyHashError("unresolved_any_operand")
            group = group_catalog.get(path)
            if group is None:
                raise DependencyHashError("unknown_group")
            try:
                resolution = resolve_group_expression(group, group_catalog, identity_map)
            except UnsafeExpression as exc:
                raise DependencyHashError(exc.code) from None
            dependencies["groups"][path] = {
                "resolved_networks": resolution.networks,
                "identity_dependencies": resolution.identity_dependencies,
                "group_dependencies": resolution.group_dependencies,
                "definition": group,
            }
    for path in rule.get("services", []):
        if path == "ANY":
            raise DependencyHashError("unresolved_any_service")
        service = service_catalog.get(path)
        if service is None:
            raise DependencyHashError("unknown_service")
        dependencies["services"][path] = service
    return digest(dependencies)
