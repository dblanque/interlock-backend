-- User
CREATE ROLE test_interlockadmin WITH PASSWORD 'Clave1234';
ALTER USER test_interlockadmin CREATEDB;
ALTER ROLE test_interlockadmin WITH LOGIN;

-- DB
CREATE DATABASE test_interlockdb;
ALTER DATABASE test_interlockdb OWNER to test_interlockadmin;
