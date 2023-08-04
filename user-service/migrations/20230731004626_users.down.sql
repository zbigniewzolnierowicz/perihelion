-- Add down migration script here
DROP TABLE IF EXISTS refresh;
DROP TABLE IF EXISTS jwt;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS users;
DROP TYPE IF EXISTS credential_type;
