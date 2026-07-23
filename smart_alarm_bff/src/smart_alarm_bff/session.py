"""Cookie session kernel for the production BFF.

The browser never receives a platform token from this module.  The token is
stored as an authenticated AES-GCM envelope and the browser receives only a
random, HttpOnly session cookie plus a one-time-readable CSRF token.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import os
import re
import secrets
from typing import Any
from uuid import UUID

from asyncpg import Pool, Record
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .policy import PolicyError, ProductPrincipal, capabilities_for_role
from .thingsboard import ThingsBoardClient, ThingsBoardError, ThingsBoardUser


SESSION_COOKIE = "__Host-smart_alarm_session"
SESSION_TTL = timedelta(hours=8)
TOKEN_KEY_VERSION = 1
_ENVELOPE_VERSION = 1
_AAD = b"smart-alarm.platform-token.v1"
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,512}$")


class SessionError(RuntimeError):
    """An expected authentication/session failure safe to expose to clients."""

    def __init__(self, code: str, *, status_code: int = 401) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii")).digest()


def parse_bearer(value: str | None) -> str:
    if not value or not value.startswith("Bearer "):
        raise SessionError("platform_authorization_required")
    token = value[7:]
    if not token or len(token) > 16_384 or any(char.isspace() for char in token):
        raise SessionError("invalid_platform_token")
    return token


class TokenCipher:
    def __init__(self, key_material: bytes) -> None:
        if len(key_material) < 32:
            raise ValueError("session key must contain at least 32 bytes")
        self._key = hashlib.sha256(key_material).digest()

    def encrypt(self, token: str) -> bytes:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, token.encode("utf-8"), _AAD)
        return bytes([_ENVELOPE_VERSION]) + nonce + ciphertext

    def decrypt(self, envelope: bytes) -> str:
        if len(envelope) < 1 + 12 + 16 or envelope[0] != _ENVELOPE_VERSION:
            raise SessionError("invalid_session", status_code=401)
        nonce = envelope[1:13]
        try:
            token = AESGCM(self._key).decrypt(nonce, envelope[13:], _AAD).decode("utf-8")
        except Exception as exc:
            raise SessionError("invalid_session", status_code=401) from exc
        if not token or len(token) > 16_384 or any(char.isspace() for char in token):
            raise SessionError("invalid_session", status_code=401)
        return token


@dataclass(frozen=True, slots=True)
class SessionContext:
    session_token: str
    platform_token: str
    principal: ProductPrincipal


class SessionService:
    def __init__(self, thingsboard: ThingsBoardClient, session_key: bytes) -> None:
        self._thingsboard = thingsboard
        self._cipher = TokenCipher(session_key)

    async def create(self, pool: Pool[Any], platform_token: str, *, now: datetime | None = None) -> tuple[SessionContext, str]:
        try:
            platform_user = await self._thingsboard.current_user(platform_token)
        except ThingsBoardError as exc:
            raise SessionError(exc.code, status_code=401) from exc
        principal = await self._load_principal(pool, platform_user)
        session_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        current = now or datetime.now(timezone.utc)
        expires = current + SESSION_TTL
        async with pool.acquire() as connection:
            await connection.execute(
                """
                INSERT INTO smart_alarm.http_sessions
                    (user_id, tenant_id, customer_id, session_digest, csrf_digest,
                     platform_token_ciphertext, platform_token_key_version,
                     policy_version, identity_version, created_at, last_seen_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11)
                """,
                principal.local_user_id,
                principal.internal_tenant_id,
                principal.internal_customer_id,
                _digest(session_token),
                _digest(csrf_token),
                self._cipher.encrypt(platform_token),
                TOKEN_KEY_VERSION,
                principal.policy_version,
                principal.identity_version,
                current,
                expires,
            )
        return SessionContext(session_token, platform_token, principal), csrf_token

    async def resolve(self, pool: Pool[Any], session_token: str | None, *, now: datetime | None = None) -> SessionContext:
        if not session_token or not _TOKEN_PATTERN.fullmatch(session_token):
            raise SessionError("session_required")
        current = now or datetime.now(timezone.utc)
        async with pool.acquire() as connection:
            row = await connection.fetchrow(self._session_query(), _digest(session_token), current)
            if row is None:
                raise SessionError("session_invalid")
            platform_token = self._cipher.decrypt(bytes(row["platform_token_ciphertext"]))
            try:
                platform_user = await self._thingsboard.current_user(platform_token)
            except ThingsBoardError as exc:
                await connection.execute(
                    "UPDATE smart_alarm.http_sessions SET revoked_at = $2 WHERE session_digest = $1 AND revoked_at IS NULL",
                    _digest(session_token), current,
                )
                raise SessionError("platform_session_invalid") from exc
            principal = self._principal_from_row(row, platform_user, session=True)
            await connection.execute(
                "UPDATE smart_alarm.http_sessions SET last_seen_at = $2 WHERE session_digest = $1 AND revoked_at IS NULL",
                _digest(session_token), current,
            )
        return SessionContext(session_token, platform_token, principal)

    async def require_csrf(self, pool: Pool[Any], session_token: str | None, csrf_token: str | None) -> None:
        if not session_token or not _TOKEN_PATTERN.fullmatch(session_token) or not csrf_token or not _TOKEN_PATTERN.fullmatch(csrf_token):
            raise SessionError("csrf_required", status_code=403)
        async with pool.acquire() as connection:
            valid = await connection.fetchval(
                """
                SELECT 1 FROM smart_alarm.http_sessions
                WHERE session_digest = $1 AND csrf_digest = $2
                  AND revoked_at IS NULL AND expires_at > clock_timestamp()
                """,
                _digest(session_token),
                _digest(csrf_token),
            )
        if valid != 1:
            raise SessionError("csrf_invalid", status_code=403)

    async def revoke(self, pool: Pool[Any], session_token: str | None, csrf_token: str | None, *, now: datetime | None = None) -> None:
        await self.require_csrf(pool, session_token, csrf_token)
        current = now or datetime.now(timezone.utc)
        async with pool.acquire() as connection:
            await connection.execute(
                "UPDATE smart_alarm.http_sessions SET revoked_at = $2 WHERE session_digest = $1 AND revoked_at IS NULL",
                _digest(session_token or ""), current,
            )

    async def _load_principal(self, pool: Pool[Any], platform_user: ThingsBoardUser) -> ProductPrincipal:
        async with pool.acquire() as connection:
            row = await connection.fetchrow(self._principal_query(), platform_user.user_id)
        if row is None:
            raise SessionError("identity_not_registered", status_code=403)
        return self._principal_from_row(row, platform_user)

    @staticmethod
    def _principal_query() -> str:
        return """
            SELECT u.id AS local_user_id, u.thingsboard_user_id, u.username, u.email,
                   u.authority, u.tenant_id AS internal_tenant_id,
                   u.customer_id AS internal_customer_id, u.status AS user_status,
                   u.identity_version, t.thingsboard_tenant_id,
                   c.thingsboard_customer_id, ra.tenant_id AS role_tenant_id,
                   ra.customer_id AS role_customer_id, pr.role_key,
                   pr.capabilities, pr.policy_version, pr.status AS role_status,
                   ra.status AS assignment_status
            FROM smart_alarm.users u
            LEFT JOIN smart_alarm.tenants t ON t.id = u.tenant_id
            LEFT JOIN smart_alarm.customers c ON c.tenant_id = u.tenant_id AND c.id = u.customer_id
            JOIN smart_alarm.role_assignments ra ON ra.user_id = u.id AND ra.status = 'ACTIVE'
            JOIN smart_alarm.product_roles pr ON pr.id = ra.role_id AND pr.status = 'ACTIVE'
            WHERE u.thingsboard_user_id = $1
        """

    @classmethod
    def _session_query(cls) -> str:
        return """
            SELECT s.platform_token_ciphertext, s.user_id AS session_user_id,
                   s.tenant_id AS session_tenant_id, s.customer_id AS session_customer_id,
                   s.policy_version AS session_policy_version,
                   s.identity_version AS session_identity_version,
                   u.id AS local_user_id, u.thingsboard_user_id, u.username, u.email,
                   u.authority, u.tenant_id AS internal_tenant_id,
                   u.customer_id AS internal_customer_id, u.status AS user_status,
                   u.identity_version, t.thingsboard_tenant_id,
                   c.thingsboard_customer_id, ra.tenant_id AS role_tenant_id,
                   ra.customer_id AS role_customer_id, pr.role_key,
                   pr.capabilities, pr.policy_version, pr.status AS role_status,
                   ra.status AS assignment_status
            FROM smart_alarm.http_sessions s
            JOIN smart_alarm.users u ON u.id = s.user_id
            LEFT JOIN smart_alarm.tenants t ON t.id = u.tenant_id
            LEFT JOIN smart_alarm.customers c ON c.tenant_id = u.tenant_id AND c.id = u.customer_id
            JOIN smart_alarm.role_assignments ra ON ra.user_id = u.id AND ra.status = 'ACTIVE'
            JOIN smart_alarm.product_roles pr ON pr.id = ra.role_id AND pr.status = 'ACTIVE'
            WHERE s.session_digest = $1 AND s.revoked_at IS NULL AND s.expires_at > $2
        """

    @classmethod
    def _principal_from_row(cls, row: Record, platform_user: ThingsBoardUser, *, session: bool = False) -> ProductPrincipal:
        if session:
            if row["session_user_id"] != row["local_user_id"]:
                raise SessionError("session_invalid")
            if row["session_tenant_id"] != row["internal_tenant_id"] or row["session_customer_id"] != row["internal_customer_id"]:
                raise SessionError("session_invalid")
            if int(row["session_policy_version"]) != int(row["policy_version"]) or int(row["session_identity_version"]) != int(row["identity_version"]):
                raise SessionError("session_revoked", status_code=401)
        if row["user_status"] != "ACTIVE" or row["role_status"] != "ACTIVE" or row["assignment_status"] != "ACTIVE":
            raise SessionError("identity_revoked", status_code=403)
        if row["thingsboard_user_id"] != platform_user.user_id or row["authority"] != platform_user.authority:
            raise SessionError("identity_mismatch", status_code=403)
        if row["username"] != platform_user.username:
            raise SessionError("identity_mismatch", status_code=403)
        internal_tenant = row["internal_tenant_id"]
        internal_customer = row["internal_customer_id"]
        mapped_tenant = row["thingsboard_tenant_id"]
        mapped_customer = row["thingsboard_customer_id"]
        if platform_user.tenant_id != mapped_tenant or platform_user.customer_id != mapped_customer:
            raise SessionError("scope_mismatch", status_code=403)
        if row["role_tenant_id"] != internal_tenant or row["role_customer_id"] != internal_customer:
            raise SessionError("role_scope_mismatch", status_code=403)
        try:
            capabilities = capabilities_for_role(row["authority"], row["role_key"], row["capabilities"])
        except (PolicyError, TypeError, ValueError) as exc:
            raise SessionError("invalid_policy", status_code=403) from exc
        return ProductPrincipal(
            local_user_id=row["local_user_id"],
            platform_user_id=platform_user.user_id,
            authority=platform_user.authority,
            product_role=row["role_key"],
            internal_tenant_id=internal_tenant,
            platform_tenant_id=platform_user.tenant_id,
            internal_customer_id=internal_customer,
            platform_customer_id=platform_user.customer_id,
            capabilities=capabilities,
            policy_version=int(row["policy_version"]),
            identity_version=int(row["identity_version"]),
        )
