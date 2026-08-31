"""Wazuh REST API client."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("soc.wazuh.client")


class WazuhAPIError(Exception):
    """Base exception for Wazuh API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class WazuhAuthError(WazuhAPIError):
    """Authentication or authorization failure with Wazuh API."""
    pass


class WazuhClient:
    """Async HTTP client for Wazuh Manager REST API (v4.x)."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        timeout: float = 15.0,
        max_retries: int = 3,
        client: Optional[httpx.AsyncClient] = None,
    ):
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries

        self._token: Optional[str] = None
        self._custom_client = client
        self._client: Optional[httpx.AsyncClient] = client

        if not self.verify_ssl:
            logger.warning("Wazuh API SSL verification is DISABLED. Insecure connections permitted.")

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=httpx.Timeout(self.timeout),
            )
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client session."""
        if self._client is not None and self._custom_client is None:
            if not self._client.is_closed:
                await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> WazuhClient:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def authenticate(self) -> str:
        """Authenticate with Wazuh API using Basic Auth and cache the JWT token."""
        if not self.base_url:
            raise WazuhAuthError("Wazuh API URL is not configured")
        if not self.username or not self.password:
            raise WazuhAuthError("Wazuh API username or password is not configured")

        client = await self._get_client()
        url = f"{self.base_url}/security/user/authenticate"

        try:
            resp = await client.post(
                url,
                auth=(self.username, self.password),
                headers={"Content-Type": "application/json"},
            )
        except httpx.TimeoutException as exc:
            logger.warning("Wazuh API authentication timed out")
            raise WazuhAPIError(f"Authentication request timed out: {exc}") from exc
        except httpx.NetworkError as exc:
            logger.warning("Wazuh API network connection failed during authentication")
            raise WazuhAPIError(f"Network connection failed: {exc}") from exc

        if resp.status_code in (401, 403):
            logger.warning("Wazuh API authentication failed (status %d)", resp.status_code)
            raise WazuhAuthError(
                f"Wazuh authentication rejected (HTTP {resp.status_code})",
                status_code=resp.status_code,
                response_body=resp.text,
            )

        if resp.status_code != 200:
            logger.warning("Wazuh API authentication error (status %d)", resp.status_code)
            raise WazuhAPIError(
                f"Authentication error (HTTP {resp.status_code})",
                status_code=resp.status_code,
                response_body=resp.text,
            )

        try:
            body = resp.json()
            # Standard Wazuh 4.x response: {"data": {"token": "..."}}
            token = body.get("data", {}).get("token") if isinstance(body.get("data"), dict) else body.get("token")
            if not token:
                raise ValueError("Response payload does not contain a valid JWT token")
            self._token = str(token)
            logger.info("Wazuh API authentication successful")
            return self._token
        except Exception as exc:
            logger.error("Failed to parse Wazuh authentication response: %s", exc)
            raise WazuhAuthError(f"Invalid authentication response structure: {exc}") from exc

    def invalidate_token(self) -> None:
        """Evict the cached JWT token."""
        self._token = None

    async def request(
        self,
        method: str,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Execute an authenticated request with JWT auto-refresh and transient retry handling."""
        if not self._token:
            await self.authenticate()

        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        client = await self._get_client()

        req_headers = dict(headers or {})
        req_headers["Authorization"] = f"Bearer {self._token}"

        attempt = 0
        refreshed_auth = False

        while attempt < self.max_retries:
            attempt += 1
            try:
                resp = await client.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json,
                    headers=req_headers,
                )
            except httpx.TimeoutException as exc:
                if attempt >= self.max_retries:
                    raise WazuhAPIError(f"Wazuh API request to {endpoint} timed out after {attempt} attempts") from exc
                backoff = 0.2 * (2 ** (attempt - 1))
                logger.warning("Wazuh request timeout, retrying in %.2fs (attempt %d/%d)", backoff, attempt, self.max_retries)
                await asyncio.sleep(backoff)
                continue
            except httpx.NetworkError as exc:
                if attempt >= self.max_retries:
                    raise WazuhAPIError(f"Wazuh API network error for {endpoint}: {exc}") from exc
                backoff = 0.2 * (2 ** (attempt - 1))
                logger.warning("Wazuh network error, retrying in %.2fs (attempt %d/%d)", backoff, attempt, self.max_retries)
                await asyncio.sleep(backoff)
                continue

            # Token expired or unauthorized — refresh once
            if resp.status_code == 401:
                if not refreshed_auth:
                    logger.info("Wazuh API returned 401, refreshing JWT token...")
                    self.invalidate_token()
                    await self.authenticate()
                    req_headers["Authorization"] = f"Bearer {self._token}"
                    refreshed_auth = True
                    continue
                else:
                    raise WazuhAuthError("Wazuh authentication failed even after token refresh", status_code=401)

            # Server error — transient retry
            if resp.status_code >= 500:
                if attempt >= self.max_retries:
                    raise WazuhAPIError(
                        f"Wazuh API server error (HTTP {resp.status_code}): {resp.text}",
                        status_code=resp.status_code,
                        response_body=resp.text,
                    )
                backoff = 0.2 * (2 ** (attempt - 1))
                logger.warning("Wazuh HTTP %d error, retrying in %.2fs (attempt %d/%d)", resp.status_code, backoff, attempt, self.max_retries)
                await asyncio.sleep(backoff)
                continue

            if not resp.is_success:
                raise WazuhAPIError(
                    f"Wazuh API request failed (HTTP {resp.status_code}): {resp.text}",
                    status_code=resp.status_code,
                    response_body=resp.text,
                )

            try:
                return resp.json()
            except Exception as exc:
                raise WazuhAPIError(f"Invalid JSON response from Wazuh API: {exc}") from exc

        raise WazuhAPIError(f"Wazuh API request failed after {self.max_retries} attempts")

    async def fetch_alerts(
        self,
        *,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 500,
        offset: int = 0,
        q: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Query security alerts from the Wazuh API with time range filters and pagination.

        Returns (alerts_list, total_count).
        """
        params: Dict[str, Any] = {
            "limit": min(limit, 500),
            "offset": max(offset, 0),
            "sort": "+timestamp",
        }

        query_parts: List[str] = []
        if time_start:
            # Format timestamp with timezone
            if time_start.tzinfo is None:
                time_start = time_start.replace(tzinfo=timezone.utc)
            query_parts.append(f"timestamp>{time_start.isoformat()}")
        if time_end:
            if time_end.tzinfo is None:
                time_end = time_end.replace(tzinfo=timezone.utc)
            query_parts.append(f"timestamp<={time_end.isoformat()}")
        if q:
            query_parts.append(q)

        if query_parts:
            params["q"] = ";".join(query_parts)

        data = await self.request("GET", "/alerts", params=params)

        # Handle standard Wazuh 4.x structure: {"data": {"affected_items": [...], "total_affected_items": N}}
        if isinstance(data, dict):
            inner_data = data.get("data", {})
            if isinstance(inner_data, dict):
                items = inner_data.get("affected_items", [])
                total = inner_data.get("total_affected_items", len(items))
                return items, total
            elif isinstance(inner_data, list):
                return inner_data, len(inner_data)

            items = data.get("items", data.get("alerts", []))
            return items, len(items)

        if isinstance(data, list):
            return data, len(data)

        return [], 0
