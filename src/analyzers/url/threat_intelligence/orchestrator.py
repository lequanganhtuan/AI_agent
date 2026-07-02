from __future__ import annotations

import asyncio
import logging
from typing import Any

import redis.asyncio as aioredis

from src.analyzers.url.threat_intelligence.config import ThreatIntelConfig
from src.analyzers.url.threat_intelligence.provider import (
    GoogleSafeBrowsingProvider,
    AbuseIPDBProvider,
    ThreatIntelInput,
    URLHausProvider,
    URLScanProvider,
    VirusTotalProvider,
)
from src.core.models import (
    GoogleSafeBrowsingAnalysis,
    AbuseIPDBAnalysis,
    ThreatIntelligenceResult,
    ThreatIntelligenceRisk,
    ThreatSignal,
    URLHausAnalysis,
    URLScanAnalysis,
    ValidationResult,
    VirusTotalAnalysis,
)
from src.core.settings import settings
from src.dns.resolver import DNSResolver
from src.analyzers.url.threat_intelligence.risk.threat_risk_calculator import ThreatRiskCalculator

logger = logging.getLogger(__name__)


class ThreatIntelOrchestrator:
    """Orchestrator coordinating DNS Resolution, parallel Threat Intelligence calls, and aggregation."""

    def __init__(self) -> None:
        # Initialize DNS Resolver
        self.dns_resolver = DNSResolver()

        # Initialize providers 
        self.virustotal = VirusTotalProvider()
        self.google_safe_browsing = GoogleSafeBrowsingProvider()
        self.urlscan = URLScanProvider()
        self.urlhaus = URLHausProvider()
        self.ip_reputation = AbuseIPDBProvider()

        # Initialize Redis Cache Client
        # Initialize Redis Cache Client
        self._redis_client = None
        if settings.redis_url:
            try:
                self._redis_client = aioredis.Redis.from_url(
                    settings.redis_url,
                    socket_timeout=1.0,
                    decode_responses=True
                )
                logger.info("[Orchestrator] Redis async client initialized successfully.")
            except Exception as exc:
                logger.warning("[Orchestrator] Redis caching system not available: %s", exc)

    # 2. CORE PIPELINE METHOD
    async def analyze_url(self, validation_result: ValidationResult) -> ThreatIntelligenceResult:
        """Core orchestrator pipeline entry point."""
        if not validation_result or not validation_result.normalized_url:
            raise ValueError("ValidationResult cannot be null or missing normalized_url")

        correlation_id = getattr(validation_result, "cache_key", "UNKNOWN-TRACE")

        # Step 1: Check cache
        cache_key = self._get_cache_key(validation_result)
        cached_result = await self._get_cached_result(cache_key)
        if cached_result:
            logger.info("[Orchestrator][%s] Cache hit detected. Returning pre-computed intelligence.", correlation_id)
            return cached_result

        # Step 2: Extract inputs 
        normalized_url = validation_result.normalized_url
        domain = validation_result.components.full_domain if validation_result.components else ""
        
        if not domain:
            logger.error("[Orchestrator][%s] Critical Error: Phase 1 leaked empty full_domain. Aborting lookup fallback.", correlation_id)
            raise ValueError("Data pipeline breach: 'components.full_domain' must be populated by Phase 1.")

        # Resolve IP address via Infrastructure Layer
        ip_address = None
        if validation_result.metadata and validation_result.metadata.is_ip:
            ip_address = domain
        else:
            dns_res = await self._resolve_dns(domain)
            if dns_res.resolved and dns_res.ips:
                ip_address = dns_res.ips[0]

        # Xây dựng DTO đầu vào bất biến cho các Provider
        threat_input = ThreatIntelInput(
            normalized_url=normalized_url,
            domain=domain,
            ip_address=ip_address,
            cache_key=validation_result.cache_key,
        )

        # Step 3: Run providers concurrently (With Observability & Latency Tracking)
        provider_data, confidence = await self._run_providers_parallel(threat_input, correlation_id)

        # Step 4: Compute normalized signals and score
        signals = self._normalize_signals(provider_data)
        risk_analysis = self._calculate_risk(signals, provider_data, confidence)

        # Step 5: Build final result
        result = ThreatIntelligenceResult(
            virustotal=provider_data["virustotal"],
            google_safe_browsing=provider_data["google_safe_browsing"],
            urlscan=provider_data["urlscan"],
            ip_reputation=provider_data["ip_reputation"],
            urlhaus=provider_data["urlhaus"],
            risk=risk_analysis,
        )

        # Step 6: Cache result
        await self._cache_result(cache_key, result)

        return result

    # 3. SUPPORTING METHODS
    async def _resolve_dns(self, domain: str) -> Any:
        """Call DNSResolver safely with fallback options."""
        try:
            return await self.dns_resolver.resolve(domain)
        except Exception as exc:
            logger.warning("[Orchestrator] Infrastructure Fault: DNS resolution failed for %s: %s", domain, exc)
            from src.dns.models import DNSResult
            return DNSResult(domain=domain, ips=[], resolved=False)

    async def _run_providers_parallel(self, threat_input: ThreatIntelInput, correlation_id: str) -> tuple[dict[str, Any], float]:
        """Execute all threat intelligence providers concurrently using asyncio.gather with Latency Metrics."""
        
        tasks = [
            self._run_single_provider(self.virustotal, threat_input, VirusTotalAnalysis.model_construct(), correlation_id),
            self._run_single_provider(self.google_safe_browsing, threat_input, GoogleSafeBrowsingAnalysis.model_construct(), correlation_id),
            self._run_single_provider(self.urlscan, threat_input, URLScanAnalysis.model_construct(), correlation_id),
            self._run_single_provider(self.urlhaus, threat_input, URLHausAnalysis.model_construct(query_status="no_match"), correlation_id),
            self._run_single_provider(self.ip_reputation, threat_input, AbuseIPDBAnalysis.model_construct(), correlation_id),
        ]

        results = await asyncio.gather(*tasks)

        # Calculate confidence as fraction of successfully executed providers
        success_count = sum(1 for _, success in results if success)
        confidence = round(success_count / len(tasks), 2) if tasks else 1.0

        provider_data = {
            "virustotal": results[0][0],
            "google_safe_browsing": results[1][0],
            "urlscan": results[2][0],
            "urlhaus": results[3][0],
            "ip_reputation": results[4][0],
        }

        return provider_data, confidence

    async def _run_single_provider(
        self, provider: Any, threat_input: ThreatIntelInput, default_val: Any, correlation_id: str
    ) -> tuple[Any, bool]:
        """Execute lookup on a single provider catching all errors safely with Observability metrics."""
        provider_name = getattr(provider, "PROVIDER_NAME", "Unknown")
        loop = asyncio.get_running_loop()
        start_time = loop.time()
        
        try:
            timeout = getattr(provider, "_timeout", 5.0) + 1.0
            result = await asyncio.wait_for(provider.lookup(threat_input), timeout=timeout)
            
            duration = loop.time() - start_time
            logger.info("[Orchestrator][%s] Provider %s fetched successfully in %.3fs.", correlation_id, provider_name, duration)
            return result, True
            
        except Exception as exc:
            duration = loop.time() - start_time
            logger.warning(
                "[Orchestrator][%s] Observability Alert: Provider %s failed/timed out after %.3fs. Falling back to empty semantic state. Error: %s",
                correlation_id, provider_name, duration, exc
            )
            try:
                default_val = default_val.model_copy(update={"error_message": str(exc)})
            except Exception:
                pass
            return default_val, False

    # 4. NORMALIZATION & SCORING LAYER
    def _normalize_signals(self, provider_data: dict[str, Any]) -> list[ThreatSignal]:

        signals = []
        # 1. VirusTotal 
        vt = provider_data.get("virustotal")
        if vt:
            malicious_count = getattr(vt, "malicious", 0)
            if malicious_count >= ThreatIntelConfig.VIRUSTOTAL_MALICIOUS_THRESHOLD:
                signals.append(ThreatSignal(code="VT_CONFIRMED_MALICIOUS", severity="critical", provider="VirusTotal"))
            elif malicious_count > 0:
                signals.append(ThreatSignal(code="VT_SUSPICIOUS", severity="high", provider="VirusTotal"))

        # 2. Google Safe Browsing 
        gsb = provider_data.get("google_safe_browsing")
        if gsb and getattr(gsb, "threat_found", False):
            signals.append(ThreatSignal(code="GOOGLE_BLACKLIST", severity="critical", provider="Google"))

        # 3. URLHaus 
        uh = provider_data.get("urlhaus")
        if uh and getattr(uh, "query_status", None) == "ok":
            if getattr(uh, "url_status", None) == "online":
                signals.append(ThreatSignal(code="URLHAUS_ACTIVE_MALWARE", severity="critical", provider="URLHaus"))
            else:
                signals.append(ThreatSignal(code="URLHAUS_INACTIVE_RECORD", severity="low", provider="URLHaus"))

        # 4. AbuseIPDB
        ab = provider_data.get("ip_reputation")
        if ab:
            abuse_score = getattr(ab, "abuse_score", 0)
            if abuse_score >= ThreatIntelConfig.ABUSEIPDB_MALICIOUS_THRESHOLD:
                signals.append(ThreatSignal(code="ABUSEIPDB_HIGH_CONFIDENCE_MALICIOUS", severity="high", provider="AbuseIPDB"))
            elif abuse_score >= ThreatIntelConfig.ABUSEIPDB_SUSPICIOUS_THRESHOLD:
                signals.append(ThreatSignal(code="ABUSEIPDB_SUSPICIOUS", severity="medium", provider="AbuseIPDB"))
            
            total_reports = getattr(ab, "total_reports", 0)
            if total_reports > ThreatIntelConfig.ABUSEIPDB_REPORTS_THRESHOLD:
                signals.append(ThreatSignal(code="ABUSEIPDB_REPORTS_FOUND", severity="medium", provider="AbuseIPDB"))
            
            usage_type = getattr(ab, "usage_type", "") or ""
            if "data center" in usage_type.lower() or "web hosting" in usage_type.lower():
                signals.append(ThreatSignal(code="ABUSEIPDB_DATACENTER_HOSTING", severity="medium", provider="AbuseIPDB"))

        # 5. URLScan 
        us = provider_data.get("urlscan")
        if us:
            final_local_score = getattr(us, "final_local_score", 0.0)
            form_risk_score = getattr(us, "form_risk_score", 0.0)
            hosting_risk_score = getattr(us, "hosting_risk_score", 0.0)

            if final_local_score >= ThreatIntelConfig.URLSCAN_LOCAL_MALICIOUS_THRESHOLD:
                signals.append(ThreatSignal(code="BEHAVIORAL_HIGH_RISK", severity="high", provider="URLScan"))
            elif final_local_score >= ThreatIntelConfig.URLSCAN_LOCAL_SUSPICIOUS_THRESHOLD:
                signals.append(ThreatSignal(code="BEHAVIORAL_SUSPICIOUS", severity="medium", provider="URLScan"))

            if form_risk_score >= ThreatIntelConfig.URLSCAN_FORM_MALICIOUS_THRESHOLD:
                signals.append(ThreatSignal(code="PHISHING_FORM_DETECTED", severity="critical", provider="URLScan"))
            elif form_risk_score >= ThreatIntelConfig.URLSCAN_FORM_SUSPICIOUS_THRESHOLD:
                signals.append(ThreatSignal(code="SUSPICIOUS_LOGIN_FIELDS", severity="high", provider="URLScan"))

            if hosting_risk_score >= ThreatIntelConfig.URLSCAN_HOSTING_SUSPICIOUS_THRESHOLD:
                signals.append(ThreatSignal(code="RISKY_ASN_HOSTING", severity="medium", provider="URLScan"))

            if getattr(us, "redirect_count", 0) > ThreatIntelConfig.URLSCAN_REDIRECT_THRESHOLD:
                signals.append(ThreatSignal(code="EXCESSIVE_REDIRECTS", severity="medium", provider="URLScan"))
                
            urlscan_global_score = getattr(us, "urlscan_global_score", 0.0)
            if urlscan_global_score >= ThreatIntelConfig.URLSCAN_GLOBAL_MALICIOUS_THRESHOLD:
                signals.append(ThreatSignal(code="URLSCAN_GLOBAL_MALICIOUS", severity="high", provider="URLScan"))

        return signals

    def _calculate_risk(
        self, signals: list[ThreatSignal], provider_data: dict[str, Any], confidence: float
    ) -> ThreatIntelligenceRisk:
        """Layer 2: Risk Calculator. Aggregates normalized signals into category buckets and compounds weights."""
        return ThreatRiskCalculator.calculate(signals, provider_data, confidence)

    # 5. CACHING LAYER (FIX ISSUE 4: Native Pydantic v2 Serialization Hooks)
    def _get_cache_key(self, validation_result: ValidationResult) -> str:
        """Generate cache key for full pipeline lookup."""
        prefix = ThreatIntelConfig.CACHE_PREFIX
        return f"{prefix}full_threat_intel:{validation_result.cache_key}"

    async def _cache_result(self, key: str, result: ThreatIntelligenceResult) -> None:
        """Persist result model into Redis cache."""
        if not self._redis_client:
            return

        try:
            data = result.model_dump_json()
            ttl = ThreatIntelConfig.DEFAULT_CACHE_TTL_SECONDS
            await self._redis_client.set(key, data, ex=ttl)
        except Exception as exc:
            logger.warning("[Orchestrator] Redis Error: Failed to write serialized telemetry to cache: %s", exc)

    async def _get_cached_result(self, key: str) -> ThreatIntelligenceResult | None:
        """Retrieve and parse result model from Redis cache safely using Native Pydantic Validation."""
        if not self._redis_client:
            return None

        try:
            data = await self._redis_client.get(key)
            if data:
                # FIX ISSUE 4: Đọc trực tiếp byte-string/string bằng Pydantic v2 Engine, chống lỗi map sai Sub-models lồng nhau
                return ThreatIntelligenceResult.model_validate_json(data)
        except Exception as exc:
            logger.warning("[Orchestrator] Redis Error: De-serialization integrity breach on cache read: %s", exc)
        return None