from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID, uuid4

from smart_alarm_bff.policy import PolicyError

try:
    from smart_alarm_bff.session import SessionError, TokenCipher, parse_bearer, SessionService
    from smart_alarm_bff.thingsboard import THINGSBOARD_NULL_UUID, ThingsBoardUser
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
            "tenantId": {"id": str(THINGSBOARD_NULL_UUID), "entityType": "TENANT"},
            "customerId": {"id": str(THINGSBOARD_NULL_UUID), "entityType": "CUSTOMER"},
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
            "tenantId": {"id": str(THINGSBOARD_NULL_UUID), "entityType": "TENANT"},
            "customerId": {"id": str(THINGSBOARD_NULL_UUID), "entityType": "CUSTOMER"},
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


@unittest.skipUnless(_missing_dependency is None, f"runtime dependency is not installed: {_missing_dependency}")
class CustomerSessionRlsTest(unittest.IsolatedAsyncioTestCase):
    async def test_customer_session_identity_uses_transaction_local_system_scope(self) -> None:
        local_tenant = uuid4()
        local_customer = uuid4()
        local_user = uuid4()
        platform_tenant = uuid4()
        platform_customer = uuid4()
        platform_user_id = uuid4()
        platform_user = ThingsBoardUser(
            platform_user_id,
            "customeradmin",
            None,
            "CUSTOMER_USER",
            platform_tenant,
            platform_customer,
        )
        principal_row = {
            "local_user_id": local_user,
            "thingsboard_user_id": platform_user_id,
            "username": "customeradmin",
            "email": None,
            "authority": "CUSTOMER_USER",
            "internal_tenant_id": local_tenant,
            "internal_customer_id": local_customer,
            "user_status": "ACTIVE",
            "identity_version": 1,
            "thingsboard_tenant_id": platform_tenant,
            "thingsboard_customer_id": platform_customer,
            "role_tenant_id": local_tenant,
            "role_customer_id": local_customer,
            "role_key": "CUSTOMER_OPERATOR",
            "capabilities": [
                "monitor:read", "alarms:read", "devices:read", "settings:read",
                "assets:read", "alarms:ack", "alarms:clear",
            ],
            "policy_version": 1,
            "role_status": "ACTIVE",
            "assignment_status": "ACTIVE",
        }

        class Context:
            def __init__(self, enter, exit=None):  # type: ignore[no-untyped-def]
                self._enter = enter
                self._exit = exit

            async def __aenter__(self):  # type: ignore[no-untyped-def]
                return self._enter()

            async def __aexit__(self, *_args: object) -> None:
                if self._exit:
                    self._exit()

        class Connection:
            def __init__(self) -> None:
                self.in_transaction = False
                self.system_scope = False
                self.system_scope_calls = 0
                self.session_values: tuple[object, ...] | None = None
                self.touch_result = 1

            def transaction(self) -> Context:
                def enter():  # type: ignore[no-untyped-def]
                    self.in_transaction = True
                    return self

                def exit() -> None:
                    self.in_transaction = False
                    self.system_scope = False

                return Context(enter, exit)

            async def execute(self, statement: str, *args: object) -> None:
                if "smart_alarm.system_scope" in statement:
                    if not self.in_transaction:
                        raise AssertionError("system scope must be transaction-local")
                    self.system_scope = True
                    self.system_scope_calls += 1
                elif "INSERT INTO smart_alarm.http_sessions" in statement:
                    self.session_values = args

            async def fetchrow(self, statement: str, *_args: object) -> dict[str, object] | None:
                self.assert_transaction_scope()
                if "FROM smart_alarm.http_sessions s" not in statement:
                    return principal_row
                if self.session_values is None:
                    return None
                return {
                    **principal_row,
                    "platform_token_ciphertext": self.session_values[5],
                    "session_user_id": self.session_values[0],
                    "session_tenant_id": self.session_values[1],
                    "session_customer_id": self.session_values[2],
                    "session_policy_version": self.session_values[7],
                    "session_identity_version": self.session_values[8],
                }

            async def fetchval(self, statement: str, *_args: object) -> int:
                if "SET last_seen_at" not in statement:
                    raise AssertionError("unexpected scalar query")
                return self.touch_result

            def assert_transaction_scope(self) -> None:
                if not self.in_transaction:
                    raise AssertionError("identity lookup must run in a transaction")
                if not self.system_scope:
                    raise AssertionError("identity lookup requires system scope")

        connection = Connection()

        class Pool:
            def acquire(self) -> Context:
                return Context(lambda: connection)

        class ThingsBoard:
            async def current_user(self, token: str) -> ThingsBoardUser:
                self.assert_token(token)
                if connection.in_transaction or connection.system_scope:
                    raise AssertionError("platform request must not retain database system scope")
                return platform_user

            @staticmethod
            def assert_token(token: str) -> None:
                if token != "platform-token":
                    raise AssertionError("unexpected platform token")

        service = SessionService(ThingsBoard(), b"k" * 32)  # type: ignore[arg-type]
        created, csrf_token = await service.create(
            Pool(), "platform-token", now=datetime(2026, 7, 24, tzinfo=timezone.utc),  # type: ignore[arg-type]
        )
        resolved = await service.resolve(
            Pool(), created.session_token, now=datetime(2026, 7, 24, 0, 1, tzinfo=timezone.utc),  # type: ignore[arg-type]
        )

        self.assertTrue(csrf_token)
        self.assertEqual(resolved.principal.internal_customer_id, local_customer)
        self.assertEqual(resolved.principal.platform_customer_id, platform_customer)
        connection.touch_result = 0
        with self.assertRaisesRegex(SessionError, "session_invalid"):
            await service.resolve(
                Pool(), created.session_token, now=datetime(2026, 7, 24, 0, 2, tzinfo=timezone.utc),  # type: ignore[arg-type]
            )
        self.assertEqual(connection.system_scope_calls, 3)
        self.assertFalse(connection.in_transaction)
        self.assertFalse(connection.system_scope)


if __name__ == "__main__":
    unittest.main()
