ALTER TABLE smart_alarm.outbox_events
    ADD COLUMN lease_token bigint NOT NULL DEFAULT 0 CHECK (lease_token >= 0),
    ADD CONSTRAINT outbox_lease_shape_ck CHECK (
        (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (status <> 'LEASED' AND lease_owner IS NULL AND lease_expires_at IS NULL)
    );

COMMENT ON COLUMN smart_alarm.outbox_events.lease_token IS
    'Monotonic fencing token; completion must match owner and token from the claim';
