-- The postgres image creates the "agentgov" database (POSTGRES_USER); Keycloak gets its own.
CREATE DATABASE keycloak OWNER agentgov;
