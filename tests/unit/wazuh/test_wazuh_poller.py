"""Unit tests for WazuhPoller background service, pagination, and watermark management."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from backend.services.wazuh_poller import WazuhPoller
from tests.fixtures.wazuh_alerts import brute_force_scenario, ssh_auth_failure


@pytest.fixture
def mock_session_factory():
    session = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.flush = AsyncMock()
    session.add = MagicMock()

    factory = MagicMock()
    factory.return_value.__aenter__ = AsyncMock(return_value=session)
    factory.return_value.__aexit__ = AsyncMock(return_value=None)
    return factory


class TestWazuhPollerExecution:
    @pytest.mark.asyncio
    async def test_poll_once_success_and_watermark_advances(self, mock_session_factory):
        mock_client = AsyncMock()
        alert = ssh_auth_failure(offset=0)
        mock_client.fetch_alerts.return_value = ([alert], 1)

        dedup_store = set()

        def _is_dup(d):
            return d in dedup_store

        def _rec_dup(ds):
            dedup_store.update(ds)

        with patch("backend.services.wazuh_poller.run_pipeline", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = (1, 1, 1)

            poller = WazuhPoller(
                client=mock_client,
                session_factory=mock_session_factory,
                poll_interval_seconds=10,
                overlap_seconds=30,
                is_duplicate_fn=_is_dup,
                record_dedup_fn=_rec_dup,
            )

            assert poller.watermark is None
            result = await poller.poll_once()

            assert result.fetched == 1
            assert result.processed == 1
            assert result.duplicates == 0
            assert poller.watermark is not None
            assert poller.total_alerts_processed == 1
            assert poller.last_error is None
            assert poller.consecutive_errors == 0
            mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_watermark_does_not_advance_on_fetch_failure(self, mock_session_factory):
        mock_client = AsyncMock()
        mock_client.fetch_alerts.side_effect = ConnectionError("Wazuh unreachable")

        poller = WazuhPoller(
            client=mock_client,
            session_factory=mock_session_factory,
        )

        with pytest.raises(ConnectionError):
            await poller.poll_once()

        assert poller.watermark is None
        assert poller.consecutive_errors == 1
        assert "Wazuh unreachable" in str(poller.last_error)

    @pytest.mark.asyncio
    async def test_watermark_does_not_advance_on_pipeline_commit_failure(self, mock_session_factory):
        mock_client = AsyncMock()
        alert = ssh_auth_failure()
        mock_client.fetch_alerts.return_value = ([alert], 1)

        poller = WazuhPoller(
            client=mock_client,
            session_factory=mock_session_factory,
        )

        with patch("backend.services.wazuh_poller.run_pipeline", new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = RuntimeError("Database deadlock")

            with pytest.raises(RuntimeError):
                await poller.poll_once()

            # Watermark must remain UNCHANGED
            assert poller.watermark is None
            assert poller.consecutive_errors == 1
            assert "Database deadlock" in str(poller.last_error)

    @pytest.mark.asyncio
    async def test_deduplication_skips_known_alerts(self, mock_session_factory):
        mock_client = AsyncMock()
        alert = ssh_auth_failure()
        mock_client.fetch_alerts.return_value = ([alert], 1)

        # Pretend alert is already in dedup cache
        poller = WazuhPoller(
            client=mock_client,
            session_factory=mock_session_factory,
            is_duplicate_fn=lambda d: True,
        )

        with patch("backend.services.wazuh_poller.run_pipeline", new_callable=AsyncMock) as mock_run:
            result = await poller.poll_once()

            assert result.fetched == 1
            assert result.processed == 0
            assert result.duplicates == 1
            # Pipeline is not invoked if all alerts are duplicates
            mock_run.assert_not_called()
            # Watermark still advances to cover the window
            assert poller.watermark is not None

    @pytest.mark.asyncio
    async def test_overlap_window_computation(self, mock_session_factory):
        mock_client = AsyncMock()
        mock_client.fetch_alerts.return_value = ([], 0)

        poller = WazuhPoller(
            client=mock_client,
            session_factory=mock_session_factory,
            overlap_seconds=45,
            initial_lookback_minutes=15,
        )

        # Initial poll: uses initial_lookback_minutes
        await poller.poll_once()
        t1 = poller.watermark
        assert t1 is not None

        # Subsequent poll: should query with t1 - 45s
        await poller.poll_once()
        call_kwargs = mock_client.fetch_alerts.call_args_list[-1].kwargs
        queried_start = call_kwargs["time_start"]
        assert (t1 - queried_start).total_seconds() == pytest.approx(45, abs=2)

    @pytest.mark.asyncio
    async def test_poller_status(self, mock_session_factory):
        mock_client = AsyncMock()
        poller = WazuhPoller(
            client=mock_client,
            session_factory=mock_session_factory,
            poll_interval_seconds=20,
        )

        status = poller.get_status()
        assert status["running"] is False
        assert status["poll_interval_seconds"] == 20
        assert status["total_alerts_fetched"] == 0
        assert status["total_alerts_processed"] == 0
        assert status["watermark"] is None

    @pytest.mark.asyncio
    async def test_graceful_start_and_stop(self, mock_session_factory):
        mock_client = AsyncMock()
        mock_client.fetch_alerts.return_value = ([], 0)
        mock_client.close = AsyncMock()

        poller = WazuhPoller(
            client=mock_client,
            session_factory=mock_session_factory,
            poll_interval_seconds=1,
        )

        await poller.start()
        assert poller.is_running is True
        assert poller._task is not None

        await asyncio.sleep(0.05)
        await poller.stop()

        assert poller.is_running is False
        assert poller._task is None
        mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_poll_locking(self, mock_session_factory):
        mock_client = AsyncMock()

        async def _slow_fetch(**kwargs):
            await asyncio.sleep(0.05)
            return ([], 0)

        mock_client.fetch_alerts.side_effect = _slow_fetch

        poller = WazuhPoller(
            client=mock_client,
            session_factory=mock_session_factory,
        )

        # Run two concurrent polls
        results = await asyncio.gather(poller.poll_once(), poller.poll_once())
        assert len(results) == 2
        assert mock_client.fetch_alerts.call_count == 2


class TestWazuhPollerPagination:
    @pytest.mark.asyncio
    async def test_multi_page_pagination_retrieval(self, mock_session_factory):
        """Test retrieving multiple pages within a single polling cycle."""
        mock_client = AsyncMock()

        page1 = [ssh_auth_failure(offset=0), ssh_auth_failure(offset=1)]
        page2 = [ssh_auth_failure(offset=2)]

        async def _paged_fetch(*, offset=0, limit=2, **kwargs):
            if offset == 0:
                return page1, 3
            elif offset == 2:
                return page2, 3
            return [], 3

        mock_client.fetch_alerts.side_effect = _paged_fetch

        with patch("backend.services.wazuh_poller.run_pipeline", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = (1, 0, 0)

            poller = WazuhPoller(
                client=mock_client,
                session_factory=mock_session_factory,
                batch_size=2,
            )

            result = await poller.poll_once()

            assert result.fetched == 3
            assert result.processed == 3
            assert result.duplicates == 0
            assert mock_client.fetch_alerts.call_count == 2
            assert mock_run.call_count == 2
            assert poller.watermark is not None

    @pytest.mark.asyncio
    async def test_watermark_not_advancing_if_second_page_fails(self, mock_session_factory):
        """If page 1 succeeds but page 2 throws a fatal error, watermark MUST NOT advance."""
        mock_client = AsyncMock()

        page1 = [ssh_auth_failure(offset=0), ssh_auth_failure(offset=1)]

        async def _failing_second_page(*, offset=0, limit=2, **kwargs):
            if offset == 0:
                return page1, 4
            raise RuntimeError("Network dropped during page 2")

        mock_client.fetch_alerts.side_effect = _failing_second_page

        with patch("backend.services.wazuh_poller.run_pipeline", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = (1, 0, 0)

            poller = WazuhPoller(
                client=mock_client,
                session_factory=mock_session_factory,
                batch_size=2,
            )

            assert poller.watermark is None

            with pytest.raises(RuntimeError, match="Network dropped during page 2"):
                await poller.poll_once()

            # Watermark must remain None (unchanged)
            assert poller.watermark is None
            assert poller.consecutive_errors == 1

    @pytest.mark.asyncio
    async def test_deduplication_across_multiple_pages(self, mock_session_factory):
        """Ensure deduplication functions properly across multi-page batches."""
        mock_client = AsyncMock()

        alert_a = ssh_auth_failure(offset=0)
        alert_b = ssh_auth_failure(offset=1)

        dedup_set = set()

        def _is_dup(d):
            return d in dedup_set

        def _rec_dup(ds):
            dedup_set.update(ds)

        # Page 1 has alert_a and alert_b, Page 2 has duplicate of alert_a
        page1 = [alert_a, alert_b]
        page2 = [alert_a]

        async def _fetch_with_dups(*, offset=0, **kwargs):
            if offset == 0:
                return page1, 3
            elif offset == 2:
                return page2, 3
            return [], 3

        mock_client.fetch_alerts.side_effect = _fetch_with_dups

        with patch("backend.services.wazuh_poller.run_pipeline", new_callable=AsyncMock) as mock_run:
            mock_run.return_value = (1, 0, 0)

            poller = WazuhPoller(
                client=mock_client,
                session_factory=mock_session_factory,
                batch_size=2,
                is_duplicate_fn=_is_dup,
                record_dedup_fn=_rec_dup,
            )

            result = await poller.poll_once()

            assert result.fetched == 3
            assert result.processed == 2
            assert result.duplicates == 1
            assert poller.total_alerts_processed == 2
            assert poller.total_duplicates == 1

    @pytest.mark.asyncio
    async def test_batch_size_capped_at_500(self, mock_session_factory):
        """Batch size above 500 must be safely clamped to 500."""
        mock_client = AsyncMock()
        poller = WazuhPoller(
            client=mock_client,
            session_factory=mock_session_factory,
            batch_size=1000,
        )
        assert poller.batch_size == 500
