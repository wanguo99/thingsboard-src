from __future__ import annotations

from pathlib import Path
import unittest

from smart_alarm_bff.migrate import load_migrations


class MigrationContractTest(unittest.TestCase):
    def test_initial_schema_covers_production_control_plane(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migrations = load_migrations(directory)
        self.assertEqual([item[0] for item in migrations], ["0001_initial.sql", "0002_seed_product_roles.sql"])
        sql = migrations[0][2]
        for table in (
            "tenants",
            "customers",
            "users",
            "product_roles",
            "role_assignments",
            "device_inventory",
            "device_profiles",
            "assets",
            "business_groups",
            "devices",
            "entity_groups",
            "entity_group_members",
            "entity_relations",
            "http_sessions",
            "operations",
            "command_approvals",
            "command_batches",
            "command_batch_items",
            "notification_events",
            "outbox_events",
            "collision_events",
            "alarm_event_log",
            "audit_events",
        ):
            self.assertIn(f"CREATE TABLE smart_alarm.{table}", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertIn("CREATE TRIGGER audit_events_append_only", sql)
        self.assertIn("credential_secret_ref", sql)

    def test_product_role_seed_matches_policy_contract(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        seed = load_migrations(directory)[1][2]
        for role in ("SYSTEM_OPERATOR", "TENANT_OWNER", "TENANT_OPERATOR", "TENANT_VIEWER", "CUSTOMER_OPERATOR", "CUSTOMER_VIEWER"):
            self.assertIn(f"('{role}'", seed)

    def test_migration_names_and_checksums_are_stable(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        for name, checksum, sql in load_migrations(directory):
            self.assertRegex(name, r"^[0-9]{4}_[a-z0-9_]+\.sql$")
            self.assertRegex(checksum, r"^[0-9a-f]{64}$")
            self.assertTrue(sql.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
