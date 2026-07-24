"""Offline factory inventory import with a least-privilege database identity."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
from uuid import UUID

from .config import ConfigError, _HOST_PATTERN, _port, _readable_file, _required, read_secret


_SERIAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$")
_SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$")
_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_EXPECTED_KEYS = {
    "schemaVersion",
    "deviceUid",
    "serialNumber",
    "deviceName",
    "claimState",
    "claimTokenHash",
    "claimExpiresAt",
    "activationRequestId",
    "ownerRef",
    "claimedAt",
    "createdAt",
}


@dataclass(frozen=True, slots=True)
class InventoryImportSettings:
    database_host: str
    database_port: int
    database_name: str
    database_user: str
    database_password: bytes = field(repr=False)
    database_tls: bool = True
    database_ca_file: Path | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "InventoryImportSettings":
        source = os.environ if env is None else env
        local = _required(source, "SMART_ALARM_ENVIRONMENT") == "local"
        host = _required(source, "SMART_ALARM_DATABASE_HOST")
        if local:
            if host not in {"127.0.0.1", "localhost", "::1"}:
                raise ConfigError("local inventory database host must be a loopback address")
        else:
            if not _HOST_PATTERN.fullmatch(host):
                raise ConfigError("SMART_ALARM_DATABASE_HOST must be a DNS hostname")
            if _required(source, "SMART_ALARM_DATABASE_SSLMODE") != "verify-full":
                raise ConfigError("SMART_ALARM_DATABASE_SSLMODE must be verify-full")
        return cls(
            database_host=host,
            database_port=_port(source, "SMART_ALARM_DATABASE_PORT"),
            database_name=_required(source, "SMART_ALARM_DATABASE_NAME"),
            database_user=_required(source, "SMART_ALARM_INVENTORY_DATABASE_USER"),
            database_password=read_secret(
                source,
                "SMART_ALARM_INVENTORY_DATABASE_PASSWORD",
                minimum_bytes=8 if local else 16,
            ),
            database_tls=not local,
            database_ca_file=None if local else _readable_file(source, "SMART_ALARM_DATABASE_CA_FILE"),
        )


@dataclass(frozen=True, slots=True)
class InventoryRecord:
    device_uid: UUID
    serial_number: str
    claim_token_hash: bytes = field(repr=False)
    claim_expires_at: datetime


def parse_inventory_record(path: Path, *, now: datetime | None = None) -> InventoryRecord:
    resolved = path.expanduser().resolve()
    try:
        mode = resolved.stat().st_mode & 0o777
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read inventory record: {resolved}") from exc
    if mode & 0o077:
        raise ValueError(f"inventory record must not be accessible by group or others: {resolved}")
    if not isinstance(payload, dict) or set(payload) != _EXPECTED_KEYS or payload.get("schemaVersion") != 1:
        raise ValueError(f"invalid inventory record schema: {resolved}")
    try:
        device_uid = UUID(str(payload.get("deviceUid")))
    except ValueError as exc:
        raise ValueError(f"invalid deviceUid: {resolved}") from exc
    if device_uid.version != 4 or str(device_uid) != payload.get("deviceUid"):
        raise ValueError(f"deviceUid must be a canonical UUIDv4: {resolved}")
    serial_number = payload.get("serialNumber")
    if not isinstance(serial_number, str) or not _SERIAL.fullmatch(serial_number):
        raise ValueError(f"invalid serialNumber: {resolved}")
    if payload.get("deviceName") != f"sad-{device_uid}":
        raise ValueError(f"deviceName does not match deviceUid: {resolved}")
    if (
        payload.get("claimState") != "AVAILABLE"
        or payload.get("activationRequestId") is not None
        or payload.get("ownerRef") is not None
        or payload.get("claimedAt") is not None
    ):
        raise ValueError(f"only unused inventory records can be imported: {resolved}")
    claim_hash = payload.get("claimTokenHash")
    match = _SHA256.fullmatch(claim_hash) if isinstance(claim_hash, str) else None
    if match is None:
        raise ValueError(f"invalid claimTokenHash: {resolved}")
    expires_at_ms = payload.get("claimExpiresAt")
    created_at_ms = payload.get("createdAt")
    if (
        not isinstance(expires_at_ms, int)
        or isinstance(expires_at_ms, bool)
        or not isinstance(created_at_ms, int)
        or isinstance(created_at_ms, bool)
        or created_at_ms < 0
        or expires_at_ms <= created_at_ms
    ):
        raise ValueError(f"invalid inventory timestamps: {resolved}")
    expires_at = datetime.fromtimestamp(expires_at_ms / 1000, timezone.utc)
    if expires_at <= (now or datetime.now(timezone.utc)):
        raise ValueError(f"claim proof is already expired: {resolved}")
    return InventoryRecord(device_uid, serial_number, bytes.fromhex(match.group(1)), expires_at)


def import_inventory_records(
    connection: Any,
    records: Sequence[InventoryRecord],
    *,
    factory_batch: str,
    hardware_model: str,
) -> dict[str, int]:
    if not records:
        raise ValueError("at least one inventory record is required")
    if not _TEXT.fullmatch(factory_batch) or not _TEXT.fullmatch(hardware_model):
        raise ValueError("factory batch and hardware model must be safe non-empty identifiers")
    if len({item.device_uid for item in records}) != len(records):
        raise ValueError("duplicate deviceUid in import batch")
    if len({item.serial_number for item in records}) != len(records):
        raise ValueError("duplicate serialNumber in import batch")
    inserted = existing = 0
    with connection.transaction():
        for record in records:
            created = connection.execute(
                """
                INSERT INTO smart_alarm.device_inventory
                    (device_uid, serial_number, claim_token_hash, claim_expires_at,
                     factory_batch, hardware_model)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING 1
                """,
                (
                    record.device_uid,
                    record.serial_number,
                    record.claim_token_hash,
                    record.claim_expires_at,
                    factory_batch,
                    hardware_model,
                ),
            ).fetchone()
            if created is not None:
                inserted += 1
                continue
            current = connection.execute(
                """
                SELECT device_uid, serial_number, claim_token_hash, claim_expires_at,
                       factory_batch, hardware_model, status, claim_consumed_at
                FROM smart_alarm.device_inventory
                WHERE device_uid = %s OR serial_number = %s
                """,
                (record.device_uid, record.serial_number),
            ).fetchone()
            expected = (
                record.device_uid,
                record.serial_number,
                record.claim_token_hash,
                record.claim_expires_at,
                factory_batch,
                hardware_model,
                "UNCLAIMED",
                None,
            )
            if current is None or tuple(current) != expected:
                raise ValueError(f"inventory identity conflict for deviceUid {record.device_uid}")
            existing += 1
    return {"inserted": inserted, "existing": existing, "total": len(records)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Import unused factory inventory records")
    parser.add_argument("inventory_files", nargs="+", type=Path)
    parser.add_argument("--factory-batch", required=True)
    parser.add_argument("--hardware-model", required=True)
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    import psycopg

    args = build_parser().parse_args(argv)
    settings = InventoryImportSettings.from_env()
    records = [parse_inventory_record(path) for path in args.inventory_files]
    with psycopg.connect(
        host=settings.database_host,
        port=settings.database_port,
        dbname=settings.database_name,
        user=settings.database_user,
        password=settings.database_password.decode("utf-8"),
        sslmode="verify-full" if settings.database_tls else "disable",
        sslrootcert=str(settings.database_ca_file) if settings.database_ca_file else None,
        application_name="smart-alarm-inventory-import",
        connect_timeout=5,
    ) as connection:
        result = import_inventory_records(
            connection,
            records,
            factory_batch=args.factory_batch,
            hardware_model=args.hardware_model,
        )
    print(json.dumps({"status": "PASS", **result}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
