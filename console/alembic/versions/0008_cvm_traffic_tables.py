"""cvm and traffic tables

Revision ID: 0008_cvm_traffic_tables
Revises: 0007_operations
Create Date: 2026-05-15
"""

from alembic import op

revision = "0008_cvm_traffic_tables"
down_revision = "0007_operations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TYPE cvm_state AS ENUM (
            'PROVISIONING',
            'RUNNING',
            'STOPPED',
            'FAILED',
            'TERMINATED'
        )
        """
    )
    op.execute(
        """
        CREATE TYPE service_principal_type AS ENUM (
            'security_cvm',
            'dev_cvm'
        )
        """
    )
    op.execute(
        """
        CREATE TYPE service_principal_token_purpose AS ENUM (
            'INGEST',
            'CA_EXPORT',
            'PROXY_AUTH'
        )
        """
    )
    op.execute(
        """
        CREATE TABLE security_cvms (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            state cvm_state NOT NULL DEFAULT 'PROVISIONING',
            fqdn VARCHAR(253) NOT NULL UNIQUE,
            instance_type VARCHAR(100) NULL,
            region VARCHAR(64) NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            compose_config TEXT NOT NULL DEFAULT '',
            txt_dns_record_id VARCHAR(100) NULL,
            cname_dns_record_id VARCHAR(100) NULL,
            error_reason TEXT NULL,
            proxy_port INT NULL,
            ca_cert_pem TEXT NULL,
            ca_export_token_plaintext VARCHAR(128) NULL,
            ca_export_token_stashed_at TIMESTAMPTZ NULL,
            expected_image_measurement CHAR(64) NULL,
            image_measurement CHAR(64) NULL,
            rtmr3_digest CHAR(96) NULL,
            attestation_verified_at TIMESTAMPTZ NULL,
            policy_version BIGINT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at TIMESTAMPTZ NULL,
            deleted_by UUID NULL REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX ux_security_cvms_entity_id_live
        ON security_cvms(entity_id)
        WHERE deleted_at IS NULL
        """
    )
    op.execute("CREATE INDEX ix_security_cvms_entity_state ON security_cvms(entity_id, state)")
    op.execute(
        """
        CREATE TABLE cvms (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            entity_id UUID NOT NULL REFERENCES entities(id) ON DELETE RESTRICT,
            state cvm_state NOT NULL DEFAULT 'PROVISIONING',
            fqdn VARCHAR(253) NOT NULL UNIQUE,
            instance_type VARCHAR(100) NOT NULL,
            region VARCHAR(64) NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            compose_config TEXT NOT NULL DEFAULT '',
            txt_dns_record_id VARCHAR(100) NULL,
            cname_dns_record_id VARCHAR(100) NULL,
            error_reason TEXT NULL,
            expected_image_measurement CHAR(64) NULL,
            image_measurement CHAR(64) NULL,
            rtmr3_digest CHAR(96) NULL,
            attestation_verified_at TIMESTAMPTZ NULL,
            owner_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            security_cvm_id UUID NULL REFERENCES security_cvms(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at TIMESTAMPTZ NULL,
            deleted_by UUID NULL REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    op.execute("CREATE INDEX ix_cvms_entity_state ON cvms(entity_id, state)")
    op.execute("CREATE INDEX ix_cvms_owner_created_at ON cvms(owner_id, created_at DESC)")
    op.execute("CREATE INDEX ix_cvms_security_cvm_id ON cvms(security_cvm_id)")
    op.execute(
        """
        CREATE TABLE cvm_profiles (
            cvm_id UUID NOT NULL REFERENCES cvms(id) ON DELETE CASCADE,
            profile_id UUID NOT NULL REFERENCES entity_profiles(id) ON DELETE RESTRICT,
            attached_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            attached_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
            PRIMARY KEY (cvm_id, profile_id)
        )
        """
    )
    op.execute("CREATE INDEX ix_cvm_profiles_profile_id ON cvm_profiles(profile_id)")
    op.execute(
        """
        CREATE TABLE cvm_ssh_keys (
            cvm_id UUID NOT NULL REFERENCES cvms(id) ON DELETE CASCADE,
            ssh_key_id UUID NOT NULL REFERENCES ssh_keys(id) ON DELETE CASCADE,
            PRIMARY KEY (cvm_id, ssh_key_id)
        )
        """
    )
    op.execute("CREATE INDEX ix_cvm_ssh_keys_ssh_key_id ON cvm_ssh_keys(ssh_key_id)")
    op.execute(
        """
        CREATE TABLE service_principal_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            principal_type service_principal_type NOT NULL,
            principal_id UUID NOT NULL,
            purpose service_principal_token_purpose NOT NULL,
            token_hash VARCHAR(128) NOT NULL UNIQUE,
            issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at TIMESTAMPTZ NULL,
            deleted_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
            CHECK (
                (principal_type = 'security_cvm' AND purpose IN ('INGEST', 'CA_EXPORT'))
                OR (principal_type = 'dev_cvm' AND purpose = 'PROXY_AUTH')
            )
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX ux_service_principal_tokens_current_purpose
        ON service_principal_tokens(principal_type, principal_id, purpose)
        WHERE deleted_at IS NULL AND expires_at IS NULL
        """
    )
    op.execute("CREATE INDEX ix_service_principal_tokens_hash ON service_principal_tokens(token_hash)")
    op.execute(
        """
        CREATE FUNCTION service_principal_parent_exists() RETURNS trigger AS $$
        BEGIN
            IF NEW.principal_type = 'security_cvm' THEN
                IF NOT EXISTS (SELECT 1 FROM security_cvms WHERE id = NEW.principal_id) THEN
                    RAISE foreign_key_violation USING MESSAGE = 'security_cvm principal_id does not exist';
                END IF;
            ELSIF NEW.principal_type = 'dev_cvm' THEN
                IF NOT EXISTS (SELECT 1 FROM cvms WHERE id = NEW.principal_id) THEN
                    RAISE foreign_key_violation USING MESSAGE = 'dev_cvm principal_id does not exist';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_service_principal_parent_exists
        BEFORE INSERT OR UPDATE OF principal_type, principal_id ON service_principal_tokens
        FOR EACH ROW EXECUTE FUNCTION service_principal_parent_exists()
        """
    )
    op.execute(
        """
        CREATE TABLE audit_anchors (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            last_seq BIGINT NOT NULL,
            last_row_hash CHAR(64) NOT NULL,
            external_anchor_uri TEXT NOT NULL,
            external_anchor_digest CHAR(64) NOT NULL,
            anchored_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            anchored_by UUID NULL REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    op.execute("CREATE INDEX ix_audit_anchors_last_seq ON audit_anchors(last_seq DESC)")
    op.execute(
        """
        CREATE TABLE traffic_log_batches (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            security_cvm_id UUID NOT NULL REFERENCES security_cvms(id) ON DELETE CASCADE,
            idempotency_key VARCHAR(128) NOT NULL,
            request_body_sha256 CHAR(64) NOT NULL,
            row_count INT NOT NULL,
            accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX ux_traffic_log_batches_idempotency
        ON traffic_log_batches(security_cvm_id, idempotency_key)
        """
    )
    op.execute("CREATE INDEX ix_traffic_log_batches_created_at ON traffic_log_batches(created_at)")
    op.execute(
        """
        CREATE TABLE traffic_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            batch_id UUID NOT NULL REFERENCES traffic_log_batches(id) ON DELETE CASCADE,
            timestamp TIMESTAMPTZ NOT NULL,
            security_cvm_id UUID NOT NULL REFERENCES security_cvms(id) ON DELETE CASCADE,
            cvm_id UUID NULL REFERENCES cvms(id) ON DELETE SET NULL,
            source_ip VARCHAR(45) NOT NULL,
            destination_ip VARCHAR(45) NOT NULL,
            destination_host VARCHAR(255) NULL,
            protocol VARCHAR(20) NOT NULL,
            port INT NOT NULL,
            method VARCHAR(20) NULL,
            path VARCHAR(2000) NULL,
            response_code INT NULL,
            bytes_transferred BIGINT NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    op.execute("CREATE INDEX ix_traffic_logs_security_timestamp ON traffic_logs(security_cvm_id, timestamp DESC)")
    op.execute("CREATE INDEX ix_traffic_logs_cvm_timestamp ON traffic_logs(cvm_id, timestamp DESC) WHERE cvm_id IS NOT NULL")
    op.execute("CREATE INDEX ix_traffic_logs_batch_id ON traffic_logs(batch_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_traffic_logs_batch_id")
    op.execute("DROP INDEX IF EXISTS ix_traffic_logs_cvm_timestamp")
    op.execute("DROP INDEX IF EXISTS ix_traffic_logs_security_timestamp")
    op.execute("DROP TABLE IF EXISTS traffic_logs")
    op.execute("DROP INDEX IF EXISTS ix_traffic_log_batches_created_at")
    op.execute("DROP INDEX IF EXISTS ux_traffic_log_batches_idempotency")
    op.execute("DROP TABLE IF EXISTS traffic_log_batches")
    op.execute("DROP INDEX IF EXISTS ix_audit_anchors_last_seq")
    op.execute("DROP TABLE IF EXISTS audit_anchors")
    op.execute("DROP TRIGGER IF EXISTS trg_service_principal_parent_exists ON service_principal_tokens")
    op.execute("DROP FUNCTION IF EXISTS service_principal_parent_exists")
    op.execute("DROP INDEX IF EXISTS ix_service_principal_tokens_hash")
    op.execute("DROP INDEX IF EXISTS ux_service_principal_tokens_current_purpose")
    op.execute("DROP TABLE IF EXISTS service_principal_tokens")
    op.execute("DROP INDEX IF EXISTS ix_cvm_ssh_keys_ssh_key_id")
    op.execute("DROP TABLE IF EXISTS cvm_ssh_keys")
    op.execute("DROP INDEX IF EXISTS ix_cvm_profiles_profile_id")
    op.execute("DROP TABLE IF EXISTS cvm_profiles")
    op.execute("DROP INDEX IF EXISTS ix_cvms_security_cvm_id")
    op.execute("DROP INDEX IF EXISTS ix_cvms_owner_created_at")
    op.execute("DROP INDEX IF EXISTS ix_cvms_entity_state")
    op.execute("DROP TABLE IF EXISTS cvms")
    op.execute("DROP INDEX IF EXISTS ix_security_cvms_entity_state")
    op.execute("DROP INDEX IF EXISTS ux_security_cvms_entity_id_live")
    op.execute("DROP TABLE IF EXISTS security_cvms")
    op.execute("DROP TYPE IF EXISTS service_principal_token_purpose")
    op.execute("DROP TYPE IF EXISTS service_principal_type")
    op.execute("DROP TYPE IF EXISTS cvm_state")
