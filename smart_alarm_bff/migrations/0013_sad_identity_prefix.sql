-- Move product identity names from the historical Smart Traffic Cone prefix.
-- The initial migration is immutable because it is checksum-protected.
ALTER TABLE smart_alarm.devices
    DROP CONSTRAINT IF EXISTS devices_technical_name_check;

UPDATE smart_alarm.device_inventory
SET serial_number = 'SAD-' || substring(serial_number FROM 5)
WHERE serial_number ~ '^STC-';

UPDATE smart_alarm.devices
SET technical_name = 'sad-' || substring(technical_name FROM 5)
WHERE technical_name ~ '^stc-';

ALTER TABLE smart_alarm.devices
    ADD CONSTRAINT devices_technical_name_sad_check
    CHECK (technical_name ~ '^sad-[0-9a-f-]{36}$');
