-- Password is 'password' encoded with BCrypt
INSERT INTO users (username, password) VALUES
('user', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqV6GYxPYCvYbiwbACCUs.bOaKpG'),
('admin', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqV6GYxPYCvYbiwbACCUs.bOaKpG')
ON CONFLICT (username) DO NOTHING;

INSERT INTO user_authorities (user_id, authority) VALUES
((SELECT id FROM users WHERE username = 'user'), 'USER'),
((SELECT id FROM users WHERE username = 'admin'), 'ADMIN')
ON CONFLICT DO NOTHING;