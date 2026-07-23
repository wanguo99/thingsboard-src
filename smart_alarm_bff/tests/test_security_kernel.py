from __future__ import annotations

import unittest
from uuid import UUID, uuid4

from smart_alarm_bff.policy import PolicyError

try:
    from smart_alarm_bff.session import SessionError, TokenCipher, parse_bearer, SessionService
    from smart_alarm_bff.thingsboard import ThingsBoardUser
except ModuleNotFoundError as exc:  # The source checkout may not have runtime wheels installed.
    _missing_dependency = exc.name
    SessionError = TokenCipher = parse_bearer = SessionService = ThingsBoardUser = None  # type: ignore[assignment]
else:
    _missing_dependency = None


@unittest.skipUnless(_missing_dependency is None, f"runtime dependency is not installed: {_missing_dependency}")
class SecurityKernelTest(unittest.TestCase):
    def test_token_envelope_is_authenticated_and_does_not_store_plaintext(self) -> None:
        cipher = TokenCipher(b"k" * 32)
        envelope = cipher.encrypt("platform-token")
        self.assertNotIn(b"platform-token", envelope)
        self.assertEqual(cipher.decrypt(envelope), "platform-token")
        tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])
        with self.assertRaises(SessionError):
            cipher.decrypt(tampered)

    def test_bearer_parser_rejects_ambiguous_authorization(self) -> None:
        self.assertEqual(parse_bearer("Bearer abc.def"), "abc.def")
        for value in (None, "Basic abc", "Bearer ", "Bearer abc def"):
            with self.subTest(value=value), self.assertRaises(SessionError):
                parse_bearer(value)

    def test_system_user_has_no_tenant_scope(self) -> None:
        user_id = str(uuid4())
        payload = {
            "id": {"id": user_id, "entityType": "USER"},
            "tenantId": {"id": "00000000-0000-0000-0000-000000000000", "entityType": "TENANT"},
            "customerId": {"id": "00000000-0000-0000-0000-000000000000", "entityType": "CUSTOMER"},
            "username": "Admin01",
            "email": "Admin@Example.com",
            "authority": "SYS_ADMIN",
        }
        user = ThingsBoardUser.from_payload(payload)
        self.assertEqual(user.user_id, UUID(user_id))
        self.assertIsNone(user.tenant_id)
        self.assertIsNone(user.customer_id)
        self.assertEqual(user.username, "admin01")
        self.assertEqual(user.email, "admin@example.com")

    def test_phone_username_does_not_require_email(self) -> None:
        user_id = str(uuid4())
        payload = {
            "id": {"id": user_id, "entityType": "USER"},
            "tenantId": {"id": "00000000-0000-0000-0000-000000000000", "entityType": "TENANT"},
            "customerId": {"id": "00000000-0000-0000-0000-000000000000", "entityType": "CUSTOMER"},
            "username": "+8613800138000",
            "email": None,
            "authority": "SYS_ADMIN",
        }
        user = ThingsBoardUser.from_payload(payload)
        self.assertEqual(user.username, "+8613800138000")
        self.assertIsNone(user.email)

    def test_non_system_user_requires_tenant(self) -> None:
        payload = {
            "id": {"id": str(uuid4())},
            "customerId": None,
            "username": "owner01",
            "email": "owner@example.com",
            "authority": "TENANT_ADMIN",
        }
        with self.assertRaises(PolicyError):
            ThingsBoardUser.from_payload(payload)

    def test_session_principal_rejects_role_scope_drift(self) -> None:
        tenant = uuid4()
        user = uuid4()
        platform_tenant = uuid4()
        platform_user = ThingsBoardUser(user, "owner01", "owner@example.com", "TENANT_ADMIN", platform_tenant, None)
        row = {
            "local_user_id": user,
            "thingsboard_user_id": user,
            "username": "owner01",
            "email": "owner@example.com",
            "authority": "TENANT_ADMIN",
            "internal_tenant_id": tenant,
            "internal_customer_id": None,
            "user_status": "ACTIVE",
            "identity_version": 1,
            "thingsboard_tenant_id": platform_tenant,
            "thingsboard_customer_id": None,
            "role_tenant_id": uuid4(),
            "role_customer_id": None,
            "role_key": "TENANT_VIEWER",
            "capabilities": ["monitor:read", "alarms:read", "devices:read", "settings:read", "customers:read", "assets:read", "device-profiles:read", "entity-groups:read"],
            "policy_version": 1,
            "role_status": "ACTIVE",
            "assignment_status": "ACTIVE",
        }
        with self.assertRaises(SessionError):
            SessionService._principal_from_row(row, platform_user)


if __name__ == "__main__":
    unittest.main()
