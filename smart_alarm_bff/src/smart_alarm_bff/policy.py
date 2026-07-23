"""Authority, product-role and capability contract shared with the frontend."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from uuid import UUID


SYSTEM_OPERATOR = frozenset({
    "settings:read",
    "system:tenants:read",
    "system:tenants:write",
    "system:users:read",
    "system:users:write",
    "system:roles:read",
    "system:roles:write",
    "system:audit:read",
})
BASE_READ_ONLY = frozenset({"monitor:read", "alarms:read", "devices:read", "settings:read"})
TENANT_READ_ONLY = frozenset({
    *BASE_READ_ONLY,
    "customers:read",
    "assets:read",
    "device-profiles:read",
    "entity-groups:read",
})
CUSTOMER_READ_ONLY = frozenset({*BASE_READ_ONLY, "assets:read"})
TENANT_OWNER = frozenset({
    *TENANT_READ_ONLY,
    "alarms:ack",
    "alarms:clear",
    "devices:register",
    "devices:metadata:update",
    "devices:assignment:update",
    "devices:command:execute",
    "devices:command:approve",
    "devices:retire",
    "customers:members:read",
    "customers:members:write",
    "customers:write",
    "assets:write",
    "device-profiles:write",
    "entity-groups:write",
})
TENANT_OPERATOR = frozenset({
    *TENANT_READ_ONLY,
    "alarms:ack",
    "alarms:clear",
    "devices:metadata:update",
    "devices:assignment:update",
    "devices:command:execute",
    "customers:members:read",
})
CUSTOMER_OPERATOR = frozenset({*CUSTOMER_READ_ONLY, "alarms:ack", "alarms:clear"})

ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    "SYSTEM_OPERATOR": SYSTEM_OPERATOR,
    "TENANT_OWNER": TENANT_OWNER,
    "TENANT_OPERATOR": TENANT_OPERATOR,
    "TENANT_VIEWER": TENANT_READ_ONLY,
    "CUSTOMER_OPERATOR": CUSTOMER_OPERATOR,
    "CUSTOMER_VIEWER": CUSTOMER_READ_ONLY,
}
AUTHORITY_ROLES: dict[str, frozenset[str]] = {
    "SYS_ADMIN": frozenset({"SYSTEM_OPERATOR"}),
    "TENANT_ADMIN": frozenset({"TENANT_OWNER", "TENANT_OPERATOR", "TENANT_VIEWER"}),
    "CUSTOMER_USER": frozenset({"CUSTOMER_OPERATOR", "CUSTOMER_VIEWER"}),
}


class PolicyError(ValueError):
    pass


def normalize_uuid(value: object, name: str, *, required: bool = True) -> UUID | None:
    if value is None and not required:
        return None
    if isinstance(value, dict):
        if set(value).difference({"id", "entityType"}):
            raise PolicyError(f"{name} entity identifier has unknown fields")
        value = value.get("id")
    try:
        result = UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise PolicyError(f"{name} must be a UUID") from exc
    return result


def capabilities_for_role(authority: str, role: str, stored: Iterable[object] | None = None) -> frozenset[str]:
    if authority not in AUTHORITY_ROLES or role not in AUTHORITY_ROLES[authority]:
        raise PolicyError("product role is incompatible with ThingsBoard authority")
    expected = ROLE_CAPABILITIES[role]
    if stored is None:
        return expected
    values = tuple(stored)
    if any(not isinstance(item, str) for item in values):
        raise PolicyError("stored capability policy contains a non-string value")
    actual = frozenset(values)
    if len(actual) != len(values) or actual != expected:
        raise PolicyError("stored capability policy does not match the application contract")
    return actual


@dataclass(frozen=True, slots=True)
class ProductPrincipal:
    local_user_id: UUID
    platform_user_id: UUID
    authority: str
    product_role: str
    internal_tenant_id: UUID | None
    platform_tenant_id: UUID | None
    internal_customer_id: UUID | None
    platform_customer_id: UUID | None
    capabilities: frozenset[str]
    policy_version: int
    identity_version: int

    def require(self, capability: str) -> None:
        if capability not in self.capabilities:
            raise PolicyError("required capability is not granted")

    def public_summary(self) -> dict[str, object]:
        return {
            "userId": str(self.platform_user_id),
            "authority": self.authority,
            "productRole": self.product_role,
            "tenantId": str(self.platform_tenant_id) if self.platform_tenant_id else None,
            "customerId": str(self.platform_customer_id) if self.platform_customer_id else None,
            "capabilities": sorted(self.capabilities),
            "policyVersion": self.policy_version,
        }
