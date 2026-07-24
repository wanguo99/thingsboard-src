from __future__ import annotations

from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import UUID

from smart_alarm_bff.inventory_import import (
    InventoryImportSettings,
    import_inventory_records,
    parse_inventory_record,
)


DEVICE_UID = "550e8400-e29b-41d4-a716-446655440000"
SERIAL = "STC-2N1T201RMV87AAE5J4CSAM8000-B"


class Result:
    def __init__(self, row=None) -> None:
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, row=None) -> None:
        self.row = row
        self.statements: list[tuple[str, object]] = []

    def transaction(self):
        return nullcontext()

    def execute(self, statement, parameters=None):
        self.statements.append((statement, parameters))
        return Result(self.row if statement.lstrip().startswith("SELECT") else None)


class InventoryImportTest(unittest.TestCase):
    def record(self, root: Path) -> Path:
        path = root / "inventory_record.json"
        payload = {
            "schemaVersion": 1,
            "deviceUid": DEVICE_UID,
            "serialNumber": SERIAL,
            "deviceName": f"stc-{DEVICE_UID}",
            "claimState": "AVAILABLE",
            "claimTokenHash": "sha256:" + hashlib.sha256(b"claim-token").hexdigest(),
            "claimExpiresAt": 2_000_000,
            "activationRequestId": None,
            "ownerRef": None,
            "claimedAt": None,
            "createdAt": 1_000,
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_parses_unclaimed_simulator_inventory_without_returning_secret_hash(self) -> None:
        with TemporaryDirectory() as directory:
            parsed = parse_inventory_record(
                self.record(Path(directory)),
                now=datetime.fromtimestamp(1, timezone.utc),
            )
        self.assertEqual(str(parsed.device_uid), DEVICE_UID)
        self.assertEqual(parsed.serial_number, SERIAL)
        self.assertNotIn("claim-token", repr(parsed))

    def test_rejects_permissive_file_and_claimed_record(self) -> None:
        with TemporaryDirectory() as directory:
            path = self.record(Path(directory))
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "group or others"):
                parse_inventory_record(path, now=datetime.fromtimestamp(1, timezone.utc))
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["claimState"] = "CLAIMED"
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "unused"):
                parse_inventory_record(path, now=datetime.fromtimestamp(1, timezone.utc))

    def test_import_is_insert_only_and_exactly_idempotent(self) -> None:
        with TemporaryDirectory() as directory:
            record = parse_inventory_record(
                self.record(Path(directory)),
                now=datetime.fromtimestamp(1, timezone.utc),
            )
        connection = Connection()
        result = import_inventory_records(
            connection,
            [record],
            factory_batch="simulator-local",
            hardware_model="smart-alarm-simulator",
        )
        self.assertEqual(result, {"inserted": 1, "existing": 0, "total": 1})
        self.assertTrue(any("INSERT INTO smart_alarm.device_inventory" in item[0] for item in connection.statements))

        row = (
            UUID(DEVICE_UID),
            SERIAL,
            record.claim_token_hash,
            record.claim_expires_at,
            "simulator-local",
            "smart-alarm-simulator",
            "UNCLAIMED",
            None,
        )
        repeated = import_inventory_records(
            Connection(row),
            [record],
            factory_batch="simulator-local",
            hardware_model="smart-alarm-simulator",
        )
        self.assertEqual(repeated, {"inserted": 0, "existing": 1, "total": 1})
        with self.assertRaisesRegex(ValueError, "conflict"):
            import_inventory_records(
                Connection((*row[:4], "different-batch", *row[5:])),
                [record],
                factory_batch="simulator-local",
                hardware_model="smart-alarm-simulator",
            )

    def test_configuration_separates_local_and_production_transport(self) -> None:
        local = InventoryImportSettings.from_env({
            "SMART_ALARM_ENVIRONMENT": "local",
            "SMART_ALARM_DATABASE_HOST": "127.0.0.1",
            "SMART_ALARM_DATABASE_PORT": "55432",
            "SMART_ALARM_DATABASE_NAME": "smart_alarm",
            "SMART_ALARM_INVENTORY_DATABASE_USER": "smart_alarm_inventory_importer",
            "SMART_ALARM_INVENTORY_DATABASE_PASSWORD": "local-password",
        })
        self.assertFalse(local.database_tls)
        self.assertNotIn("local-password", repr(local))
        with self.assertRaisesRegex(ValueError, "loopback"):
            InventoryImportSettings.from_env({
                **{
                    "SMART_ALARM_ENVIRONMENT": "local",
                    "SMART_ALARM_DATABASE_PORT": "55432",
                    "SMART_ALARM_DATABASE_NAME": "smart_alarm",
                    "SMART_ALARM_INVENTORY_DATABASE_USER": "smart_alarm_inventory_importer",
                    "SMART_ALARM_INVENTORY_DATABASE_PASSWORD": "local-password",
                },
                "SMART_ALARM_DATABASE_HOST": "database.internal",
            })


if __name__ == "__main__":
    unittest.main()
