INSERT INTO users (id, username, email, display_name)
VALUES
('00000000-0000-0000-0000-000000000000', 'jimmyjimmyjimmy', 'jimmy@example.com', 'Jimmy'),
('00000000-0000-0000-0000-000000000001', 'adamadamadam', 'adam@example.com', 'Adam');

INSERT INTO credentials (user_id, credential_type, credential_content)
VALUES
-- password: "password"
('00000000-0000-0000-0000-000000000000', 'password', '$argon2id$v=19$m=19456,t=2,p=1$VHX1M7Nwj2H9Ji6MuweWrg$5QeAA9uaoX6rn7DXnCKygf3CKHZ6/jc6ZKWaOWnlcT0'),
-- password: "password"
('00000000-0000-0000-0000-000000000001', 'password', '$argon2id$v=19$m=19456,t=2,p=1$VHX1M7Nwj2H9Ji6MuweWrg$5QeAA9uaoX6rn7DXnCKygf3CKHZ6/jc6ZKWaOWnlcT0');
