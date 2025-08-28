BEGIN TRANSACTION;
-- 1. First verify current data
SELECT id,
    status
FROM documents
LIMIT 10;
-- 2. Add new column with proper constraints
ALTER TABLE documents
ADD COLUMN new_status VARCHAR(20) CONSTRAINT valid_status CHECK (
        new_status IN (
            'UPLOADED',
            'PROCESSING',
            'READY',
            'SIGNED',
            'ERROR'
        )
    );
-- 3. Convert data (with transaction-safe batch updates if large table)
UPDATE documents
SET new_status = CASE
        status
        WHEN 0 THEN 'UPLOADED'
        WHEN 1 THEN 'PROCESSING'
        WHEN 2 THEN 'READY'
        WHEN 3 THEN 'SIGNED'
        WHEN 4 THEN 'ERROR'
        ELSE 'ERROR' -- Handle unexpected values gracefully
    END;
-- 4. Verify conversion before dropping old column
SELECT status,
    new_status
FROM documents
LIMIT 100;
-- 5. Drop old column and rename (in same transaction)
ALTER TABLE documents DROP COLUMN status;
ALTER TABLE documents
    RENAME COLUMN new_status TO status;
COMMIT;
-- Consider creating a Flyway/Liquibase migration file for this change (better for production)
-- If you want even stricter DB-level validation:
sql
ALTER TABLE documents
ADD CONSTRAINT valid_status CHECK (
        status IN (
            'UPLOADED',
            'PROCESSING',
            'READY',
            'SIGNED',
            'ERROR'
        )
    );
-- @Enumerated(EnumType.STRING)  // ← This is the key annotation
-- @Column(length = 20)          // Optional but recommended for database schema
-- private Status status;
-- Then use this simple migration:
sql -- Single-step conversion (PostgreSQL specific)
ALTER TABLE documents
ALTER COLUMN status TYPE VARCHAR(20) USING (
        CASE
            status
            WHEN 0 THEN 'UPLOADED'
            WHEN 1 THEN 'PROCESSING'
            WHEN 2 THEN 'READY'
            WHEN 3 THEN 'SIGNED'
            WHEN 4 THEN 'ERROR'
            ELSE 'ERROR'
        END
    );
-- Create new simplified role storage
CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role VARCHAR(20) NOT NULL,
    PRIMARY KEY (user_id, role),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
-- Create the user_roles join table if it doesn't exist
CREATE TABLE IF NOT EXISTS user_roles (
    user_id BIGINT NOT NULL,
    role VARCHAR(20) NOT NULL,
    PRIMARY KEY (user_id, role),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
-- Assign ADMIN to user with id=1
INSERT INTO user_roles (user_id, role)
VALUES (1, 'ADMIN') ON CONFLICT (user_id, role) DO NOTHING;
-- Assign MANAGER to user with id=2
INSERT INTO user_roles (user_id, role)
VALUES (2, 'MANAGER') ON CONFLICT (user_id, role) DO NOTHING;
-- Assign MANAGER to user with id=3
INSERT INTO user_roles (user_id, role)
VALUES (3, 'MANAGER') ON CONFLICT (user_id, role) DO NOTHING;
-- First clear any existing roles for these users (optional)
DELETE FROM user_roles
WHERE user_id IN (1, 2, 3);
-- Then add the new roles
INSERT INTO user_roles (user_id, role)
VALUES (1, 'ADMIN'),
    (2, 'MANAGER'),
    (3, 'MANAGER');
CREATE TABLE verification_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(255) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    expiry_date TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    token_type VARCHAR(50) NOT NULL,
    CONSTRAINT fk_verification_token_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_verification_tokens_token ON verification_tokens(token);
CREATE INDEX idx_verification_tokens_user_id ON verification_tokens(user_id);
CREATE INDEX idx_verification_tokens_expiry_date ON verification_tokens(expiry_date);
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    description VARCHAR(500) NOT NULL,
    user_id BIGINT NULL,
    username VARCHAR(100) NULL,
    user_email VARCHAR(255) NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(500) NULL,
    metadata TEXT NULL,
    created_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_user_email ON audit_logs(user_email);
create table verification_token (
    id bigint not null,
    token varchar(255),
    user_id bigint not null,
    primary key (id),
    constraint FK_VERIFICATION_TOKEN_USER foreign key (user_id) references users(id)
);