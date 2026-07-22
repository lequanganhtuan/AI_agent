from __future__ import annotations
from src.core.models import PageSnapshot, RedirectAnalysis
from src.analyzers.url.dynamic_analysis.utils.url_utils import get_apex_domain, check_ip_attributes

class RedirectAnalyzer:
    """Analyzer responsible for analyzing redirect chains without direct dependencies on Playwright APIs."""

    def analyze(self, snapshot: PageSnapshot) -> RedirectAnalysis:
        """
        Analyze redirect characteristics from a PageSnapshot.

        Args:
            snapshot: PageSnapshot containing the redirect chain.

        Returns:
            RedirectAnalysis: Data-only analysis results.
        """
        chain = snapshot.redirect_chain or []
        count = len(chain) - 1 if len(chain) > 0 else 0

        # 1. Loop detection: Check if any normalized URL is visited twice
        seen = set()
        has_redirect_loop = False
        for url in chain:
            norm = url.lower().rstrip('/')
            if norm in seen:
                has_redirect_loop = True
                break
            seen.add(norm)

        # 2. Cross domain redirect: check if any hop switches registrable domain
        has_cross_domain_redirect = False
        if len(chain) > 1:
            first_domain = get_apex_domain(chain[0])
            for url in chain[1:]:
                if get_apex_domain(url) != first_domain:
                    has_cross_domain_redirect = True
                    break

        # 3. Target host checking for redirects (hops 1 to end)
        redirects_to_ip = False
        redirects_to_localhost = False
        redirects_to_private_ip = False

        for url in chain[1:]:
            is_ip, is_local, is_priv = check_ip_attributes(url)
            if is_ip:
                redirects_to_ip = True
            if is_local:
                redirects_to_localhost = True
            if is_priv:
                redirects_to_private_ip = True

        return RedirectAnalysis(
            redirect_count=count,
            redirect_chain=chain,
            has_redirect_loop=has_redirect_loop,
            has_cross_domain_redirect=has_cross_domain_redirect,
            redirects_to_ip=redirects_to_ip,
            redirects_to_localhost=redirects_to_localhost,
            redirects_to_private_ip=redirects_to_private_ip
        )
