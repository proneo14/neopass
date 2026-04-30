-- Verify final state
SELECT om.user_id, u.email, om.role,
       om.escrow_blob IS NOT NULL as has_escrow,
       om.encrypted_org_key IS NOT NULL as has_org_key,
       length(om.escrow_blob) as escrow_len,
       length(om.encrypted_org_key) as orgkey_len
FROM org_members om
JOIN users u ON u.id = om.user_id;
