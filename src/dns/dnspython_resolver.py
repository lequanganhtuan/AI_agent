from __future__ import annotations

import logging
import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

_GLOBAL_RESOLVER = dns.resolver.Resolver()
_GLOBAL_RESOLVER.timeout = 2.0
_GLOBAL_RESOLVER.lifetime = 2.0


def resolve_dns(domain: str) -> list[str]:
    """Resolve A and AAAA records for a domain synchronously using dnspython.
    
    Args:
        domain: The domain name to resolve.
        
    Returns:
        A list of resolved IP addresses.
    """
    if not domain:
        return []

    domain = domain.strip()
    ips: list[str] = []

    # 1. Resolve A records (IPv4)
    try:
        answers_a = _GLOBAL_RESOLVER.resolve(domain, "A")
        for rdata in answers_a:
            ips.append(str(rdata.address))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        logger.debug("[dnspython_resolver] A record query failed for %s: %s", domain, exc)
    except dns.exception.DNSException as exc:
        logger.warning("[dnspython_resolver] A record query encountered error for %s: %s", domain, exc)

    # 2. Resolve AAAA records (IPv6)
    try:
        answers_aaaa = _GLOBAL_RESOLVER.resolve(domain, "AAAA")
        for rdata in answers_aaaa:
            ips.append(str(rdata.address))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        logger.debug("[dnspython_resolver] AAAA record query failed for %s: %s", domain, exc)
    except dns.exception.DNSException as exc:
        logger.warning("[dnspython_resolver] AAAA record query encountered error for %s: %s", domain, exc)

    return sorted(set(ips))