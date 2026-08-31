"""Wazuh REST API alert poller service."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.services.log_service import run_pipeline
from backend.services.wazuh_adapter import (
    WazuhAlert,
    compute_dedup_hash,
    normalize_wazuh_alerts,
)
from backend.services.wazuh_client import WazuhClient

logger = logging.getLogger("soc.wazuh.poller")

MAX_PAGES_PER_POLL = 100


class WazuhPollResponse(BaseModel):
    """Response returned by a manual or background poll cycle."""

    fetched: int
    processed: int
    duplicates: int
    watermark: Optional[str] = None
    errors: List[str] = Field(default_factory=list)


class WazuhPoller:
    """Background polling worker for incremental Wazuh alert retrieval."""

    def __init__(
        self,
        client: WazuhClient,
        session_factory: async_sessionmaker[AsyncSession],
        poll_interval_seconds: int = 30,
        overlap_seconds: int = 30,
        initial_lookback_minutes: int = 60,
        batch_size: int = 500,
        is_duplicate_fn: Optional[Callable[[str], bool]] = None,
        record_dedup_fn: Optional[Callable[[List[str]], None]] = None,
    ):
        self.client = client
        self.session_factory = session_factory
        self.poll_interval_seconds = max(poll_interval_seconds, 1)
        self.overlap_seconds = max(overlap_seconds, 0)
        self.initial_lookback_minutes = max(initial_lookback_minutes, 1)
        self.batch_size = min(max(batch_size, 1), 500)

        self._is_duplicate_fn = is_duplicate_fn or (lambda d: False)
        self._record_dedup_fn = record_dedup_fn or (lambda ds: None)

        self.is_running: bool = False
        self.watermark: Optional[datetime] = None
        self.last_attempted_poll: Optional[datetime] = None
        self.last_successful_poll: Optional[datetime] = None
        self.total_alerts_fetched: int = 0
        self.total_alerts_processed: int = 0
        self.total_duplicates: int = 0
        self.last_error: Optional[str] = None
        self.consecutive_errors: int = 0

        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start background polling task."""
        if self.is_running:
            return
        self.is_running = True
        logger.info(
            "Starting Wazuh alert poller (interval=%ds, lookback=%dm, overlap=%ds, batch_size=%d)",
            self.poll_interval_seconds,
            self.initial_lookback_minutes,
            self.overlap_seconds,
            self.batch_size,
        )
        self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        """Stop background polling task and close client cleanly."""
        self.is_running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self.client.close()
        logger.info("Wazuh alert poller stopped")

    async def poll_once(self) -> WazuhPollResponse:
        """Execute a single polling cycle across bounded pages.

        Thread-safe and concurrency-safe via asyncio.Lock.
        Advances watermark ONLY after all matching pages have been successfully
        processed and committed to the database.
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            self.last_attempted_poll = now

            if self.watermark is None:
                time_start = now - timedelta(minutes=self.initial_lookback_minutes)
            else:
                time_start = self.watermark - timedelta(seconds=self.overlap_seconds)

            time_end = now
            errors: List[str] = []

            total_fetched_cycle = 0
            total_processed_cycle = 0
            total_duplicates_cycle = 0
            max_alert_time: Optional[datetime] = None

            offset = 0

            for page_num in range(MAX_PAGES_PER_POLL):
                try:
                    raw_alerts, total_count = await self.client.fetch_alerts(
                        time_start=time_start,
                        time_end=time_end,
                        limit=self.batch_size,
                        offset=offset,
                    )
                except Exception as exc:
                    self.consecutive_errors += 1
                    self.last_error = str(exc)
                    logger.warning("Wazuh alert fetch error at offset %d: %s", offset, exc)
                    # Watermark remains UNCHANGED on failure
                    raise

                if not raw_alerts:
                    break

                total_fetched_cycle += len(raw_alerts)

                valid_alerts: List[WazuhAlert] = []
                for raw in raw_alerts:
                    try:
                        alert = WazuhAlert.model_validate(raw)
                        valid_alerts.append(alert)
                    except Exception as val_exc:
                        err_msg = f"Alert validation failed: {val_exc}"
                        logger.debug(err_msg)
                        errors.append(err_msg)

                fresh_alerts: List[WazuhAlert] = []
                fresh_digests: List[str] = []

                for alert in valid_alerts:
                    digest = compute_dedup_hash(alert)
                    if self._is_duplicate_fn(digest):
                        total_duplicates_cycle += 1
                        continue

                    fresh_alerts.append(alert)
                    fresh_digests.append(digest)

                    # Track latest alert timestamp
                    try:
                        ts_str = alert.timestamp.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(ts_str)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        if max_alert_time is None or dt > max_alert_time:
                            max_alert_time = dt
                    except Exception:
                        pass

                if fresh_alerts:
                    normalized = normalize_wazuh_alerts(fresh_alerts)
                    try:
                        async with self.session_factory() as db:
                            events_parsed, events_flagged, incidents_created = await run_pipeline(
                                db, [], "", _pre_normalized=normalized
                            )
                            await db.commit()

                        self._record_dedup_fn(fresh_digests)
                        total_processed_cycle += len(fresh_alerts)
                        logger.info(
                            "Wazuh page %d processed (offset=%d): fetched=%d processed=%d duplicates=%d flagged=%d incidents=%d",
                            page_num + 1,
                            offset,
                            len(raw_alerts),
                            len(fresh_alerts),
                            len(valid_alerts) - len(fresh_alerts),
                            events_flagged,
                            incidents_created,
                        )
                    except Exception as pipe_exc:
                        self.consecutive_errors += 1
                        self.last_error = f"Pipeline commit failed at offset {offset}: {pipe_exc}"
                        logger.exception("Wazuh pipeline processing error during poll page")
                        # Do NOT advance watermark if database commit failed
                        raise

                offset += len(raw_alerts)

                # Stop pagination if:
                # 1. Received fewer alerts than requested batch_size (end of stream)
                # 2. Offset reached or exceeded total_count reported by Wazuh API
                if len(raw_alerts) < self.batch_size or offset >= total_count:
                    break

            # Advance watermark ONLY after all pages are successfully processed and committed
            if max_alert_time and max_alert_time > time_start:
                self.watermark = max_alert_time
            else:
                self.watermark = time_end

            self.total_alerts_fetched += total_fetched_cycle
            self.total_alerts_processed += total_processed_cycle
            self.total_duplicates += total_duplicates_cycle
            self.last_successful_poll = time_end
            self.consecutive_errors = 0
            self.last_error = None

            return WazuhPollResponse(
                fetched=total_fetched_cycle,
                processed=total_processed_cycle,
                duplicates=total_duplicates_cycle,
                watermark=self.watermark.isoformat() if self.watermark else None,
                errors=errors,
            )

    async def _poll_loop(self) -> None:
        """Internal loop executing poll cycles periodically with exponential backoff on error."""
        while self.is_running:
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Wazuh poll loop iteration failed: %s", exc)

            # Dynamic backoff if consecutive errors occur
            if self.consecutive_errors > 0:
                backoff_factor = min(self.consecutive_errors - 1, 4)
                sleep_seconds = min(self.poll_interval_seconds * (2 ** backoff_factor), 120)
                logger.info("Wazuh poller backing off for %ds due to errors", sleep_seconds)
            else:
                sleep_seconds = self.poll_interval_seconds

            try:
                await asyncio.sleep(sleep_seconds)
            except asyncio.CancelledError:
                break

    def get_status(self) -> Dict[str, Any]:
        """Return diagnostic status of the poller."""
        return {
            "running": self.is_running,
            "poll_interval_seconds": self.poll_interval_seconds,
            "overlap_seconds": self.overlap_seconds,
            "watermark": self.watermark.isoformat() if self.watermark else None,
            "last_attempted_poll": self.last_attempted_poll.isoformat() if self.last_attempted_poll else None,
            "last_successful_poll": self.last_successful_poll.isoformat() if self.last_successful_poll else None,
            "total_alerts_fetched": self.total_alerts_fetched,
            "total_alerts_processed": self.total_alerts_processed,
            "total_duplicates": self.total_duplicates,
            "consecutive_errors": self.consecutive_errors,
            "last_error": self.last_error,
        }
