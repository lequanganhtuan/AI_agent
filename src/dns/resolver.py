from __future__ import annotations

import asyncio
import logging
from src.dns.models import DNSResult
from src.dns.cache import DNSCache
from src.dns.dnspython_resolver import resolve_dns

logger = logging.getLogger(__name__)


class DNSResolver:
    """DNS Resolver coordinating cache lookups and asynchronous resolution threads."""

    def __init__(self) -> None:
        self._cache = DNSCache()
        self._timeout_seconds = 3.0  # Max timeout guard (2-3s max)

    async def resolve(self, domain: str) -> DNSResult:
        """Asynchronously resolve DNS A/AAAA records for a domain with caching and timeouts.

        Guarantees:
        - Never blocks the event loop.
        - Always returns a safe result (DNSResult).
        - Never raises fatal errors.
        - Always cache-first.
        - Supports multi-IP domains.
        - Fails gracefully.
        """
        if not domain:
            return DNSResult(domain="", ips=[], resolved=False)

        domain = domain.strip().lower()

        try:
            # Step 1: Cache-First Lookup
            cached_ips = await self._cache.get(domain)
            if cached_ips is not None:
                logger.info("[DNSResolver] Cache hit for domain %s: %s", domain, cached_ips)
                return DNSResult(
                    domain=domain,
                    ips=cached_ips,
                    resolved=True if cached_ips else False
                )

            # Step 2: Resolve using threadpool with timeout protection
            logger.info("[DNSResolver] Cache miss for domain %s. Initiating lookup.", domain)
            try:
                # Run resolver in threadpool to avoid blocking event loop
                ips = await asyncio.wait_for(
                    asyncio.to_thread(resolve_dns, domain),
                    timeout=self._timeout_seconds
                )
                resolved = len(ips) > 0
            except asyncio.TimeoutError:
                logger.warning(
                    "[DNSResolver] Resolution timed out for domain %s after %.1fs",
                    domain, self._timeout_seconds
                )
                ips = []
                resolved = False
            except Exception as exc:
                logger.error("[DNSResolver] Resolution exception for domain %s: %s", domain, exc)
                ips = []
                resolved = False

            # Step 3: Cache the Result
            try:
                # Standard TTL of 1800s on success; negative-cache with 300s TTL on empty answers
                ttl = 1800 if resolved else 300
                await self._cache.set(domain, ips, ttl=ttl)
            except Exception as exc:
                logger.debug("[DNSResolver] Failed to write cache for domain %s: %s", domain, exc)

            return DNSResult(
                domain=domain,
                ips=ips,
                resolved=resolved
            )

        except Exception as exc:
            # Absolute safety guard: never propagate fatal errors
            logger.critical("[DNSResolver] Critical failure resolved as fallback for %s: %s", domain, exc)
            return DNSResult(
                domain=domain,
                ips=[],
                resolved=False
            )
