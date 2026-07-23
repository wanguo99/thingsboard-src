from __future__ import annotations

import asyncio
import json
import unittest
from uuid import UUID

import httpx

from smart_alarm_bff.thingsboard import THINGSBOARD_NULL_UUID, ThingsBoardClient, ThingsBoardError


TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
CUSTOMER_ID = UUID("22222222-2222-4222-8222-222222222222")
USER_ID = UUID("33333333-3333-4333-8333-333333333333")


def entity(value: UUID, entity_type: str) -> dict[str, str]:
    return {"id": str(value), "entityType": entity_type}


def user_payload(username: str = "+8613800138000", email: str | None = None) -> dict[str, object]:
    return {
        "id": entity(USER_ID, "USER"),
        "tenantId": entity(TENANT_ID, "TENANT"),
        "customerId": entity(CUSTOMER_ID, "CUSTOMER"),
        "username": username,
        "email": email,
        "authority": "CUSTOMER_USER",
        "additionalInfo": {"userActivated": False},
    }


class ThingsBoardUserLifecycleTest(unittest.TestCase):
    @staticmethod
    def execute(handler, scenario):  # type: ignore[no-untyped-def]
        async def run():  # type: ignore[no-untyped-def]
            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(base_url="https://tb.example.com", transport=transport) as http:
                client = ThingsBoardClient("https://tb.example.com", client=http)
                return await scenario(client)

        return asyncio.run(run())

    def test_provision_phone_user_without_email_and_disable_credentials(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.path == "/api/user":
                payload = json.loads(request.content)
                self.assertEqual(payload["username"], "+8613800138000")
                self.assertIsNone(payload["email"])
                self.assertEqual(payload["customerId"], entity(CUSTOMER_ID, "CUSTOMER"))
                self.assertNotIn("password", payload)
                return httpx.Response(200, json=user_payload())
            if request.url.path.endswith("/activationLink"):
                return httpx.Response(200, text="https://tb.example.com/api/noauth/activate?activateToken=one-time-token")
            if request.url.path == "/api/noauth/activate":
                self.assertEqual(json.loads(request.content), {"activateToken": "one-time-token", "password": "development-password"})
                self.assertNotIn("Authorization", request.headers)
                return httpx.Response(200, json={"token": "discarded", "refreshToken": "discarded"})
            return httpx.Response(200)

        user = self.execute(handler, lambda client: client.provision_user(
            "admin.jwt", username="+8613800138000", email=None,
            authority="CUSTOMER_USER", tenant_id=TENANT_ID, customer_id=CUSTOMER_ID,
            password="development-password", enabled=False,
        ))
        self.assertEqual(user.user_id, USER_ID)
        self.assertEqual([request.url.path for request in requests], [
            "/api/user", f"/api/user/{USER_ID}/activationLink", "/api/noauth/activate",
            f"/api/user/{USER_ID}/userCredentialsEnabled",
        ])

    def test_login_accepts_phone_username_and_returns_only_access_token(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/api/auth/login")
            self.assertEqual(
                json.loads(request.content),
                {"username": "+8613800138000", "password": "development-password"},
            )
            return httpx.Response(200, json={"token": "platform.jwt", "refreshToken": "discarded.jwt"})

        token = self.execute(
            handler,
            lambda client: client.login("+8613800138000", "development-password"),
        )
        self.assertEqual(token, "platform.jwt")

    def test_current_system_user_normalizes_official_null_entity_ids(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "id": entity(USER_ID, "USER"),
                "tenantId": entity(THINGSBOARD_NULL_UUID, "TENANT"),
                "customerId": entity(THINGSBOARD_NULL_UUID, "CUSTOMER"),
                "username": "sysadmin01",
                "email": "admin@example.com",
                "authority": "SYS_ADMIN",
            })

        user = self.execute(handler, lambda client: client.current_user("platform.jwt"))
        self.assertIsNone(user.tenant_id)
        self.assertIsNone(user.customer_id)

    def test_login_error_does_not_expose_password(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="password=development-password")

        with self.assertRaisesRegex(ThingsBoardError, "invalid_platform_credentials") as raised:
            self.execute(handler, lambda client: client.login("operator01", "development-password"))
        self.assertNotIn("development-password", str(raised.exception))

    def test_activation_failure_rolls_back_platform_user(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.path == "/api/user":
                return httpx.Response(200, json=user_payload("viewer01", "viewer@example.com"))
            if request.url.path.endswith("/activationLink"):
                return httpx.Response(200, text="not-an-activation-link")
            return httpx.Response(200)

        with self.assertRaises(ThingsBoardError):
            self.execute(handler, lambda client: client.provision_user(
                "admin.jwt", username="viewer01", email="viewer@example.com",
                authority="CUSTOMER_USER", tenant_id=TENANT_ID, customer_id=CUSTOMER_ID,
                password="development-password", enabled=True,
            ))
        self.assertEqual(requests[-1].method, "DELETE")
        self.assertEqual(requests[-1].url.path, f"/api/user/{USER_ID}")

    def test_credentials_status_and_delete_fail_closed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403)

        with self.assertRaisesRegex(ThingsBoardError, "platform_user_operation_forbidden"):
            self.execute(handler, lambda client: client.set_user_enabled("admin.jwt", USER_ID, True))
        with self.assertRaisesRegex(ThingsBoardError, "platform_user_operation_forbidden"):
            self.execute(handler, lambda client: client.delete_user("admin.jwt", USER_ID))


if __name__ == "__main__":
    unittest.main()
