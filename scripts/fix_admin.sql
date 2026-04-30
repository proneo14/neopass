UPDATE users SET
  auth_hash = convert_to('$2a$10$pTQP7kMvbNDSniK/rXyStuHshHFXQhCXkLdqymKiBnDe/9naL2te.', 'UTF8'),
  salt = decode('bdab980a6a1d6c133eb3bdd069768e3777461706c478c684d20d3a7b8cd69cf3', 'hex'),
  public_key = decode('302a300506032b656e032100bd492480b717a5c810b481f6288affcb81b810c6487c7717bca57f5bef3baf3d', 'hex'),
  encrypted_private_key = decode('b911328731aab7426a5cec814a00f25168def28e4ae50461eee2b1005b2a4507ad900b769273797fafde0a7d5380cf44c60f00308a0685eef3f5efeda1e5feb86fa6df8433bb1f3a79aa8811', 'hex')
WHERE email = 'admin@lgi.com';
