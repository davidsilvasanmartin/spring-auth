-- Password is 'password' encoded with BCrypt
MERGE INTO users (username, password) KEY(username) VALUES
('user', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqV6GYxPYCvYbiwbACCUs.bOaKpG'),
('admin', '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqV6GYxPYCvYbiwbACCUs.bOaKpG');

MERGE INTO user_authorities (user_id, authority) KEY(user_id, authority) VALUES
((SELECT id FROM users WHERE username = 'user'), 'USER'),
((SELECT id FROM users WHERE username = 'admin'), 'ADMIN');