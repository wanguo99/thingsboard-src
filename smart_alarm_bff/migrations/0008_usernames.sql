ALTER TABLE smart_alarm.users
    ADD COLUMN username text;

UPDATE smart_alarm.users
SET username = lower(email);

ALTER TABLE smart_alarm.users
    ALTER COLUMN username SET NOT NULL,
    ALTER COLUMN email DROP NOT NULL,
    DROP CONSTRAINT IF EXISTS users_email_check,
    DROP CONSTRAINT IF EXISTS users_tenant_id_email_key,
    ADD CONSTRAINT users_username_format_ck CHECK (
        username = lower(btrim(username))
        AND username ~ '^([a-z0-9][a-z0-9._@-]{1,62}[a-z0-9]|\+[0-9]{3,63})$'
    ),
    ADD CONSTRAINT users_optional_email_format_ck CHECK (
        email IS NULL OR (
            email = lower(btrim(email))
            AND length(email) <= 320
            AND position('@' IN email) > 1
        )
    );

DROP INDEX IF EXISTS smart_alarm.users_active_email_uq;

CREATE UNIQUE INDEX users_active_username_uq
    ON smart_alarm.users (username)
    WHERE status <> 'ARCHIVED';

CREATE INDEX users_contact_email_idx
    ON smart_alarm.users (lower(email))
    WHERE email IS NOT NULL AND status <> 'ARCHIVED';
