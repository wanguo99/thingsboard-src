INSERT INTO smart_alarm.product_roles (role_key, authority, capabilities, policy_version)
VALUES
    ('SYSTEM_OPERATOR', 'SYS_ADMIN', '["settings:read", "system:tenants:read", "system:tenants:write", "system:users:read", "system:users:write", "system:roles:read", "system:roles:write", "system:audit:read"]'::jsonb, 1),
    ('TENANT_OWNER', 'TENANT_ADMIN', '["monitor:read", "alarms:read", "devices:read", "settings:read", "customers:read", "assets:read", "device-profiles:read", "entity-groups:read", "alarms:ack", "alarms:clear", "devices:register", "devices:metadata:update", "devices:assignment:update", "devices:command:execute", "devices:command:approve", "devices:retire", "customers:members:read", "customers:members:write", "customers:write", "assets:write", "device-profiles:write", "entity-groups:write"]'::jsonb, 1),
    ('TENANT_OPERATOR', 'TENANT_ADMIN', '["monitor:read", "alarms:read", "devices:read", "settings:read", "customers:read", "assets:read", "device-profiles:read", "entity-groups:read", "alarms:ack", "alarms:clear", "devices:metadata:update", "devices:assignment:update", "devices:command:execute", "customers:members:read"]'::jsonb, 1),
    ('TENANT_VIEWER', 'TENANT_ADMIN', '["monitor:read", "alarms:read", "devices:read", "settings:read", "customers:read", "assets:read", "device-profiles:read", "entity-groups:read"]'::jsonb, 1),
    ('CUSTOMER_OPERATOR', 'CUSTOMER_USER', '["monitor:read", "alarms:read", "devices:read", "settings:read", "assets:read", "alarms:ack", "alarms:clear"]'::jsonb, 1),
    ('CUSTOMER_VIEWER', 'CUSTOMER_USER', '["monitor:read", "alarms:read", "devices:read", "settings:read", "assets:read"]'::jsonb, 1)
ON CONFLICT (role_key) DO NOTHING;
