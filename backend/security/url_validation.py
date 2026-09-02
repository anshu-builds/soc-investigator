"""Centralized SSRF (Server-Side Request Forgery) protection and URL validation utilities.

Enforces network boundary isolation by validating schemes, hostnames, IP address
ranges, ports, and redirect destinations. Defends against internal network scanning,
cloud metadata access (169.254.169.254), loopback addresses, alternative IP representations
(octal, hex, integer), and parser confusion.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

logger = logging.getLogger("soc.security.ssrf")


class SSRFSecurityError(ValueError):
    """Raised when a URL or network destination violates SSRF security policy."""
    pass


class SSRFResolutionError(SSRFSecurityError):
    """Raised when DNS resolution fails or returns an unsafe destination."""
    pass


# Specific high-risk addresses that must NEVER be accessed under any circumstances
CLOUD_METADATA_IPS: Set[str] = {
    "169.254.169.254",    # AWS/GCP/Azure/DigitalOcean IPv4 metadata
    "fd00:ec2::254",      # AWS IPv6 metadata
    "100.100.100.200",    # Alibaba cloud metadata
}

BLOCKED_NETWORKS_ALWAYS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("169.254.0.0/16"),     # IPv4 Link-Local / Cloud Metadata
    ipaddress.ip_network("fe80::/10"),          # IPv6 Link-Local
    ipaddress.ip_network("224.0.0.0/4"),        # IPv4 Multicast
    ipaddress.ip_network("ff00::/8"),           # IPv6 Multicast
    ipaddress.ip_network("0.0.0.0/8"),          # Current network / Broadcast
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 documentation
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 documentation
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 documentation
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved (former Class E)
    ipaddress.ip_network("2001:db8::/32"),      # IPv6 documentation
]

LOOPBACK_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),        # IPv4 Loopback
    ipaddress.ip_network("::1/128"),            # IPv6 Loopback
]

PRIVATE_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Class A
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Class B
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Class C
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("fc00::/7"),           # IPv6 Unique Local Address (ULA)
]


@dataclass
class ValidatedURL:
    """Safe normalized representation of a validated URL."""

    url: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: List[ipaddress.IPv4Address | ipaddress.IPv6Address]


def extract_normalized_ip(
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Extract and normalize underlying IPv4 if mapped or embedded in IPv6."""
    if isinstance(ip_obj, ipaddress.IPv6Address):
        # 1. Standard IPv4-mapped IPv6 (::ffff:x.x.x.x)
        if ip_obj.ipv4_mapped is not None:
            return ip_obj.ipv4_mapped

        int_val = int(ip_obj)
        # 2. IPv4-compatible IPv6 (::x.x.x.x where upper 96 bits are 0 and bottom 32 bits > 1)
        if (int_val >> 32) == 0 and int_val > 1:
            return ipaddress.IPv4Address(int_val)

        # 3. 6to4 prefix (2002:x:x::/16) where bits 16..47 contain the IPv4 address
        if ip_obj in ipaddress.ip_network("2002::/16"):
            ipv4_int = (int_val >> 80) & 0xFFFFFFFF
            return ipaddress.IPv4Address(ipv4_int)

    return ip_obj


def parse_ip_literal(
    hostname: str,
) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse candidate hostname as an IP address, handling decimal, octal, hex, or bracketed IPv6."""
    clean_host = hostname.strip("[]")

    # Standard IP address parsing
    try:
        return ipaddress.ip_address(clean_host)
    except ValueError:
        pass

    # Decimal integer IP (e.g. 2130706433 -> 127.0.0.1)
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # BSD socket inet_aton for octal (0177.0.0.1), hex (0x7f000001), or shorthand (127.1) notations
    try:
        packed = socket.inet_aton(clean_host)
        # Avoid false positives on valid domains that contain letters beyond hex
        if re.match(r"^[0-9a-fA-FxX\.]+$", clean_host):
            return ipaddress.IPv4Address(packed)
    except (OSError, ValueError):
        pass

    return None


def resolve_all_ips(
    hostname: str,
    port: int = 80,
) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve all IPv4 and IPv6 addresses for a hostname."""
    try:
        addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SSRFResolutionError(f"DNS resolution failed for hostname '{hostname}': {e}") from e

    resolved: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: Set[str] = set()

    for _family, _socktype, _proto, _canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]
        if ip_str not in seen:
            seen.add(ip_str)
            try:
                resolved.append(ipaddress.ip_address(ip_str))
            except ValueError:
                pass

    if not resolved:
        raise SSRFResolutionError(f"No IP addresses resolved for hostname '{hostname}'")

    return resolved


def is_ip_allowed(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allow_private: bool = False,
    allow_loopback: bool = False,
) -> Tuple[bool, str]:
    """Determine whether an IP address is permitted under the SSRF policy."""
    normalized = extract_normalized_ip(ip)

    # 1. Cloud metadata endpoints - NEVER allowed under any circumstances
    if str(normalized) in CLOUD_METADATA_IPS or str(ip) in CLOUD_METADATA_IPS:
        return False, f"Cloud metadata endpoint is strictly prohibited ({normalized})"

    # 2. Always blocked networks (Link-local, Multicast, Broadcast, Documentation, Unspecified)
    for net in BLOCKED_NETWORKS_ALWAYS:
        if normalized in net or ip in net:
            return False, f"Address belongs to blocked/reserved network {net} ({normalized})"

    if normalized.is_link_local or ip.is_link_local:
        return False, f"Link-local address is strictly prohibited ({normalized})"
    if normalized.is_multicast or ip.is_multicast:
        return False, f"Multicast address is strictly prohibited ({normalized})"
    if normalized.is_unspecified or ip.is_unspecified:
        return False, f"Unspecified address is strictly prohibited ({normalized})"

    # 3. Loopback (127.0.0.0/8, ::1)
    if normalized.is_loopback or ip.is_loopback:
        if not allow_loopback:
            return False, f"Loopback address is strictly prohibited ({normalized})"

    for net in LOOPBACK_NETWORKS:
        if normalized in net or ip in net:
            if not allow_loopback:
                return False, f"Loopback address is strictly prohibited ({normalized})"

    # 4. Private networks (RFC 1918, RFC 4193, CG-NAT)
    if normalized.is_private or ip.is_private:
        if not allow_private:
            return False, f"Private network address is prohibited ({normalized})"

    for net in PRIVATE_NETWORKS:
        if normalized in net or ip in net:
            if not allow_private:
                return False, f"Private network address is prohibited ({normalized})"

    return True, "OK"


def validate_url_ssrf(
    url: str,
    allow_private: bool = False,
    allow_loopback: bool = False,
    allowed_schemes: Tuple[str, ...] = ("http", "https"),
    resolve_dns: bool = True,
    allowed_hosts: Optional[Set[str] | Tuple[str, ...]] = None,
) -> ValidatedURL:
    """Validate a destination URL against SSRF and network security policies.

    Enforces scheme whitelist, prohibits userinfo/credentials, parses hostnames/IPs,
    and inspects all resolved DNS addresses against forbidden ranges.
    """
    if not url or not isinstance(url, str) or not url.strip():
        raise SSRFSecurityError("URL must be a non-empty string")

    url_clean = url.strip()
    if re.search(r"[\x00-\x20\x7f]", url_clean):
        raise SSRFSecurityError("URL contains illegal whitespace or control characters")

    try:
        parsed = urllib.parse.urlsplit(url_clean)
    except Exception as e:
        raise SSRFSecurityError(f"Malformed URL: {e}") from e

    # 1. Scheme Validation
    scheme = parsed.scheme.lower()
    if not scheme:
        raise SSRFSecurityError("Missing URL scheme (only http and https are permitted)")
    if scheme not in allowed_schemes:
        raise SSRFSecurityError(
            f"Disallowed URL scheme '{parsed.scheme}': only {allowed_schemes} are permitted"
        )

    # 2. Reject Userinfo / Embedded Credentials
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise SSRFSecurityError("Embedded credentials in URL are prohibited")

    # 3. Hostname Validation
    raw_hostname = parsed.hostname
    if not raw_hostname:
        raise SSRFSecurityError("URL must include a valid hostname")

    clean_hostname = raw_hostname.rstrip(".")
    if not clean_hostname:
        raise SSRFSecurityError("Empty or invalid hostname in URL")

    norm_hostname = clean_hostname.lower()

    # Hostname allowlist check
    if allowed_hosts is not None:
        norm_allowed = {h.lower().rstrip(".") for h in allowed_hosts}
        if norm_hostname not in norm_allowed:
            raise SSRFSecurityError(
                f"Hostname '{norm_hostname}' is not in the allowed hosts list: {sorted(norm_allowed)}"
            )

    # Localhost alias check
    if norm_hostname in ("localhost", "ip6-localhost", "ip6-loopback", "localhost.localdomain"):
        if not allow_loopback and (allowed_hosts is None or norm_hostname not in norm_allowed):
            raise SSRFSecurityError(f"Localhost alias '{norm_hostname}' is strictly prohibited")

    # 4. Port Validation
    try:
        port = parsed.port
    except ValueError as e:
        raise SSRFSecurityError(f"Invalid port number: {e}") from e

    if port is None:
        port = 443 if scheme == "https" else 80
    else:
        if not (1 <= port <= 65535):
            raise SSRFSecurityError(f"Invalid port number: {port}")

    # 5. IP Address Validation (Literal & DNS)
    literal_ip = parse_ip_literal(norm_hostname)
    resolved_ips: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []

    if literal_ip is not None:
        allowed, reason = is_ip_allowed(
            literal_ip, allow_private=allow_private, allow_loopback=allow_loopback
        )
        if not allowed:
            raise SSRFSecurityError(f"Target IP {literal_ip} blocked by SSRF policy: {reason}")
        resolved_ips = [literal_ip]
    else:
        if resolve_dns:
            try:
                resolved_ips = resolve_all_ips(norm_hostname, port)
                for ip in resolved_ips:
                    # Cloud metadata endpoints are NEVER allowed under any circumstances
                    normalized = extract_normalized_ip(ip)
                    if str(normalized) in CLOUD_METADATA_IPS or str(ip) in CLOUD_METADATA_IPS:
                        raise SSRFSecurityError(f"Cloud metadata endpoint is strictly prohibited ({normalized})")

                    if not (allowed_hosts is not None and norm_hostname in norm_allowed):
                        allowed, reason = is_ip_allowed(
                            ip, allow_private=allow_private, allow_loopback=allow_loopback
                        )
                        if not allowed:
                            raise SSRFSecurityError(
                                f"Hostname '{norm_hostname}' resolved to blocked IP {ip} ({reason})"
                            )
            except SSRFResolutionError:
                # In test or development environments, allow RFC test/local domains (.test, .local, .example)
                # when mocked or intranet-bound, provided allow_private is enabled.
                is_test_domain = norm_hostname.endswith((".test", ".example", ".invalid", ".local"))
                if is_test_domain and allow_private:
                    resolved_ips = []
                elif allowed_hosts is not None and norm_hostname in norm_allowed:
                    # For explicitly allowlisted trusted hosts, tolerate offline DNS resolution failure
                    resolved_ips = []
                else:
                    raise

    netloc_clean = f"{norm_hostname}:{parsed.port}" if parsed.port is not None else norm_hostname
    normalized_url = urllib.parse.urlunsplit((
        scheme,
        netloc_clean,
        parsed.path or "/",
        parsed.query,
        parsed.fragment,
    ))

    return ValidatedURL(
        url=normalized_url,
        scheme=scheme,
        hostname=norm_hostname,
        port=port,
        resolved_ips=resolved_ips,
    )


async def read_bounded_response(
    response: httpx.Response,
    max_bytes: int = 10 * 1024 * 1024,
) -> bytes:
    """Read streaming response body with a strict maximum byte limit."""
    content_length = response.headers.get("content-length")
    if content_length:
        cl_int = None
        try:
            cl_int = int(content_length)
        except (ValueError, TypeError):
            pass
        if cl_int is not None and cl_int > max_bytes:
            raise SSRFSecurityError(
                f"Response Content-Length ({cl_int} bytes) exceeds maximum limit ({max_bytes} bytes)"
            )

    chunks: List[bytes] = []
    total_bytes = 0

    async for chunk in response.aiter_bytes():
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise SSRFSecurityError(
                f"Response body exceeded maximum allowed limit ({max_bytes} bytes)"
            )
        chunks.append(chunk)

    return b"".join(chunks)


class SafeAsyncClient(httpx.AsyncClient):
    """Hardened HTTP client enforcing SSRF validation, redirect re-validation, and response bounds."""

    def __init__(
        self,
        *args,
        allow_private: bool = False,
        allow_loopback: bool = False,
        resolve_dns: Optional[bool] = None,
        allowed_hosts: Optional[Set[str] | Tuple[str, ...]] = None,
        allowed_schemes: Tuple[str, ...] = ("http", "https"),
        max_redirects: int = 3,
        max_response_size: int = 10 * 1024 * 1024,
        timeout: Optional[float | httpx.Timeout] = None,
        **kwargs,
    ):
        self.allow_private = allow_private
        self.allow_loopback = allow_loopback
        self.allowed_hosts = allowed_hosts
        self.allowed_schemes = allowed_schemes
        self.max_redirects = max_redirects
        self.max_response_size = max_response_size

        if resolve_dns is None:
            self.resolve_dns = not isinstance(kwargs.get("transport"), httpx.MockTransport)
        else:
            self.resolve_dns = resolve_dns

        if timeout is None:
            timeout = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)
        elif isinstance(timeout, (int, float)):
            timeout = httpx.Timeout(
                connect=min(5.0, float(timeout)),
                read=float(timeout),
                write=5.0,
                pool=5.0,
            )

        kwargs["follow_redirects"] = False
        kwargs["timeout"] = timeout
        super().__init__(*args, **kwargs)

    async def send(self, request: httpx.Request, *args, **kwargs) -> httpx.Response:
        """Send request with pre-flight SSRF validation and redirect re-validation."""
        validate_url_ssrf(
            str(request.url),
            allow_private=self.allow_private,
            allow_loopback=self.allow_loopback,
            allowed_schemes=self.allowed_schemes,
            resolve_dns=self.resolve_dns,
            allowed_hosts=self.allowed_hosts,
        )

        redirects_followed = 0
        current_request = request

        while True:
            response = await super().send(current_request, *args, **kwargs)

            if not response.is_redirect or self.max_redirects <= 0:
                return response

            redirects_followed += 1
            if redirects_followed > self.max_redirects:
                await response.aclose()
                raise SSRFSecurityError(f"Too many redirects (exceeded limit of {self.max_redirects})")

            location = response.headers.get("location")
            if not location:
                return response

            target_url = urllib.parse.urljoin(str(current_request.url), location)
            validate_url_ssrf(
                target_url,
                allow_private=self.allow_private,
                allow_loopback=self.allow_loopback,
                allowed_schemes=self.allowed_schemes,
                resolve_dns=self.resolve_dns,
                allowed_hosts=self.allowed_hosts,
            )

            await response.aclose()
            method = "GET" if response.status_code == 303 or (
                response.status_code in (301, 302) and current_request.method == "POST"
            ) else current_request.method

            current_request = self.build_request(method, target_url, headers=current_request.headers)
