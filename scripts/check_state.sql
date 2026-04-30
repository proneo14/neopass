-- Clean up stale data after takeover reset admin@lgi.com's keys

-- Check current state
SELECT u.id, u.email FROM users u WHERE u.email = 'admin@lgi.com';

-- Show collection memberships for admin
SELECT cm.collection_id, c.name, cm.user_id, u.email
FROM collection_members cm
JOIN users u ON u.id = cm.user_id
JOIN collections c ON c.id = cm.collection_id
WHERE u.email = 'admin@lgi.com';

-- Show all collections
SELECT c.id, c.name, c.org_id FROM collections c;

-- Show all collection members
SELECT cm.collection_id, cm.user_id, u.email FROM collection_members cm JOIN users u ON u.id = cm.user_id;

-- Show emergency access records
SELECT ea.id, ea.grantor_id, ea.grantee_id, ea.status, ea.access_type,
       g1.email as grantor_email, g2.email as grantee_email
FROM emergency_access ea
JOIN users g1 ON g1.id = ea.grantor_id
JOIN users g2 ON g2.id = ea.grantee_id;

-- Show vault entries for admin
SELECT ve.id, ve.entry_type, ve.user_id, u.email
FROM vault_entries ve
JOIN users u ON u.id = ve.user_id
WHERE u.email = 'admin@lgi.com';
