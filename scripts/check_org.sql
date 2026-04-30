-- Check org state
SELECT id, encrypted_org_private_key IS NOT NULL as has_priv_key,
       org_public_key IS NOT NULL as has_pub_key
FROM organizations;

-- Check org members and their escrow/key state
SELECT om.org_id, om.user_id, u.email, om.role,
       om.escrow_blob IS NOT NULL as has_escrow,
       om.encrypted_org_key IS NOT NULL as has_org_key
FROM org_members om
JOIN users u ON u.id = om.user_id;
