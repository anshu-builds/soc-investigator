"""Add is_active to users table.

Revision ID: 0002_user_is_active
Revises: 0001_sec08
Create Date: 2026-09-02
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0002_user_is_active"
down_revision: Union[str, None] = "0001_sec08"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Idempotently add is_active column to users table if it does not exist
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'is_active'
            ) THEN
                ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;
            END IF;
        END $$;
        """
    )
    # 2. Ensure any existing rows have is_active set to TRUE
    op.execute("UPDATE users SET is_active = TRUE WHERE is_active IS NULL;")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS is_active;")
