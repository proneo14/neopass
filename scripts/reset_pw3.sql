UPDATE users SET auth_hash = convert_to('$2a$10$Fjg4mshNvmgCUjVcnYDP7eAsTn79nt/nz5LL7Lr6sUnElvkaoCRoC', 'UTF8') WHERE email = 'admin@lgi.com';
