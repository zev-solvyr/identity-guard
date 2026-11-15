-- V1__init_auth_schema.sql

CREATE TABLE app_user (
                          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                          email VARCHAR(255) UNIQUE NOT NULL,
                          password VARCHAR(255) NOT NULL,
                          role VARCHAR(255) NOT NULL DEFAULT 'ROLE_USER',
                          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE refresh_token (
                               id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                               user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
                               token VARCHAR(512) UNIQUE NOT NULL,
                               expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
                               revoked BOOLEAN NOT NULL DEFAULT false
);

-- Index for fast lookups when validating a refresh token
CREATE INDEX idx_refresh_token_string ON refresh_token(token);