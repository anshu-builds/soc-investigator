"""SEC-08: Add dedup_hash to security_events and create audit_logs table.

Revision ID: 0001_sec08
Revises: None
Create Date: 2026-09-01
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0001_sec08"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Idempotently add dedup_hash column to security_events
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'security_events' AND column_name = 'dedup_hash'
            ) THEN
                ALTER TABLE security_events ADD COLUMN dedup_hash VARCHAR(64);
            END IF;
        END $$;
        """
    )

    # 2. Idempotently create unique index and btree index on dedup_hash
    # In PostgreSQL, standard UNIQUE permits multiple NULL values while enforcing uniqueness for non-NULL values
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'uq_security_events_dedup_hash'
            ) THEN
                ALTER TABLE security_events
                ADD CONSTRAINT uq_security_events_dedup_hash UNIQUE (dedup_hash);
            END IF;
        END $$;
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_security_events_dedup_hash
        ON security_events (dedup_hash);
        """
    )

    # 3. Idempotently create audit_logs table
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY,
            timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
            actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            action VARCHAR(100) NOT NULL,
            entity_type VARCHAR(100) NOT NULL,
            entity_id VARCHAR(255),
            source_ip VARCHAR(45),
            user_agent VARCHAR(500),
            previous_state JSONB,
            new_state JSONB,
            details JSONB,
            status VARCHAR(20) NOT NULL DEFAULT 'SUCCESS'
        );
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_audit_logs_timestamp ON audit_logs (timestamp);
        CREATE INDEX IF NOT EXISTS ix_audit_logs_actor_user_id ON audit_logs (actor_user_id);
        CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs (action);
        CREATE INDEX IF NOT EXISTS ix_audit_logs_entity_type ON audit_logs (entity_type);
        CREATE INDEX IF NOT EXISTS ix_audit_logs_entity_id ON audit_logs (entity_id);
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_logs;")
    op.execute(
        """
        ALTER TABLE security_events
        DROP CONSTRAINT IF EXISTS uq_security_events_dedup_hash;
        """
    )
    op.execute("DROP INDEX IF EXISTS ix_security_events_dedup_hash;")
    op.execute("ALTER TABLE security_events DROP COLUMN IF EXISTS dedup_hash;")
