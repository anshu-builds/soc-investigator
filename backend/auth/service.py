from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth.security import hash_password, verify_password
from backend.config import get_settings
from backend.models import User

logger = logging.getLogger("soc.auth")


async def authenticate_user(
    db: AsyncSession,
    email: str,
    password: str,
) -> Optional[User]:
    """Authenticate user with email and password."""
    if not email or not password:
        return None

    clean_email = email.strip().lower()
    result = await db.execute(select(User).where(User.email == clean_email))
    user = result.scalar_one_or_none()

    if not user:
        return None

    if not verify_password(password, user.password_hash):
        return None

    if not getattr(user, "is_active", True):
        return None

    return user


async def ensure_seed_admin(db: AsyncSession) -> User:
    """Ensure the configured seed admin exists in database on startup."""
    settings = get_settings()
    admin_email = settings.seed_admin_email.strip().lower()

    result = await db.execute(select(User).where(User.email == admin_email))
    user = result.scalar_one_or_none()

    if user is None:
        user = User(
            email=admin_email,
            password_hash=hash_password(settings.seed_admin_password),
            role="admin",
            is_active=True,
        )
        db.add(user)
        await db.flush()
        logger.info("Initialized seed admin account: %s", admin_email)

    return user
