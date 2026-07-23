from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from src.analyzers.url.threat_intelligence.config import ThreatIntelConfig
from src.analyzers.url.threat_intelligence.provider.base_provider import (
    BaseThreatProvider,
    ProviderError,
    ThreatIntelInput,
)
from src.core.models import URLScanAnalysis
from src.core.settings import settings

logger = logging.getLogger(__name__)


class URLScanProvider(BaseThreatProvider[URLScanAnalysis]):

    PROVIDER_NAME: str = "URLScan"
    MAX_CONSECUTIVE_404: int = 20  

    HIGH_RISK_ASNS: tuple[str, ...] = ("AS13335", "AS20473")
    RISKY_TLDS: tuple[str, ...] = (".xyz", ".top", ".club", ".work")

    # 1. __init__()
    def __init__(self) -> None:
        """Initialize provider with configuration thresholds and isolated credentials."""
        api_key = settings.urlscan_api_key
        base_url = ThreatIntelConfig.URLSCAN_BASE_URL
        submit_endpoint = ThreatIntelConfig.URLSCAN_SUBMIT_ENDPOINT
        result_endpoint = ThreatIntelConfig.URLSCAN_RESULT_ENDPOINT

        if not api_key:
            logger.error(
                "[%s] Initialization failed: API key not configured.",
                self.PROVIDER_NAME,
            )
            raise ValueError("URLSCAN_API_KEY is not configured")

        if not base_url or not submit_endpoint or not result_endpoint:
            logger.error(
                "[%s] Initialization failed: Invalid configuration constants.",
                self.PROVIDER_NAME,
            )
            raise ValueError("URLScan configuration constants are missing")

        super().__init__(ThreatIntelConfig.URLSCAN_TIMEOUT_SECONDS)

        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._submit_url_path = submit_endpoint
        self._result_url_path = result_endpoint
        # Cấu hình Polling Lifecycle tối đa
        self._poll_interval = ThreatIntelConfig.URLSCAN_POLL_INTERVAL_SECONDS
        self._max_poll_time = 15  # Extended to 15 seconds to allow URLScan submission processing
        self._max_poll_attempts = (
            self._max_poll_time // self._poll_interval if self._poll_interval > 0 else 1
        )

        logger.info("[%s] Provider initialized successfully.", self.PROVIDER_NAME)

    # 2. lookup() - Public Orchestrator
    async def lookup(
        self, threat_input: ThreatIntelInput, **kwargs: Any
    ) -> URLScanAnalysis:
        """Orchestrate submission, backoff polling, and pure parsing safely."""
        url = threat_input.normalized_url.strip() if threat_input.normalized_url else ""

        if not url:
            logger.error(
                "[%s] Validation failed: target normalized_url is missing.",
                self.PROVIDER_NAME,
            )
            raise ValueError("Target input normalized_url cannot be null or empty")

        # Whitelist bypass for popular clean domains to avoid URLScan blocks/restrictions
        domain_lower = threat_input.domain.lower().strip()
        parts = domain_lower.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain_lower
        
        legitimate_domains = {
            "google.com", "gmail.com", "youtube.com", "facebook.com", "apple.com",
            "microsoft.com", "live.com", "outlook.com", "twitter.com", "x.com",
            "linkedin.com", "netflix.com", "wikipedia.org", "amazon.com",
            "github.com", "cloudflare.com", "abuse.ch", "virustotal.com"
        }
        if root_domain in legitimate_domains:
            logger.info("[%s] Domain %s is in the legitimate whitelist. Returning default clean analysis.", self.PROVIDER_NAME, domain_lower)
            return URLScanAnalysis()

        logger.info(ThreatIntelConfig.LOG_REQUEST_START, self.PROVIDER_NAME, url)

        # Check URLScan history first to avoid slow fresh crawls if a recent scan exists (last 24 hours)
        try:
            search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain_lower}"
            logger.info("[%s] Querying search history for domain: %s", self.PROVIDER_NAME, domain_lower)
            search_response = await self._safe_request(
                method="GET",
                url=search_url,
                headers=self._get_minimal_auth_headers(),
                raise_for_status=False
            )
            if search_response.status_code == 200:
                search_data = self._validate_and_extract_json(search_response)
                results = search_data.get("results", [])
                if results:
                    # Find the most recent scan
                    recent_scan = results[0]
                    task_info = recent_scan.get("task", {})
                    scan_time_str = task_info.get("time")
                    scan_uuid = recent_scan.get("task", {}).get("uuid") or recent_scan.get("_id")
                    
                    if scan_time_str and scan_uuid:
                        if scan_time_str.endswith("Z"):
                            scan_time_str = scan_time_str[:-1] + "+00:00"
                        from datetime import datetime, timezone
                        scan_time = datetime.fromisoformat(scan_time_str)
                        age = datetime.now(timezone.utc) - scan_time
                        if age.total_seconds() < 24 * 60 * 60:
                            logger.info("[%s] Recent scan found (UUID: %s, Age: %.1fh). Fetching pre-compiled result.", self.PROVIDER_NAME, scan_uuid, age.total_seconds() / 3600)
                            result_endpoint = f"{self._base_url}/result/{scan_uuid}"
                            result_response = await self._safe_request(
                                method="GET",
                                url=result_endpoint,
                                headers=self._get_minimal_auth_headers(),
                                raise_for_status=False
                            )
                            if result_response.status_code == 200:
                                result_dto = self.parse_response(result_response, scan_uuid, **kwargs)
                                logger.info(ThreatIntelConfig.LOG_REQUEST_SUCCESS, self.PROVIDER_NAME)
                                return result_dto
                            else:
                                logger.warning("[%s] Failed to fetch result for historical scan %s. Status: %d", self.PROVIDER_NAME, scan_uuid, result_response.status_code)
        except Exception as e:
            logger.warning("[%s] Search history lookup failed or timed out. Proceeding to fresh crawl fallback. Error: %s", self.PROVIDER_NAME, str(e))

        try:
            # BƯỚC 1: Đẩy URL vào hàng đợi Sandbox và lấy UUID
            scan_uuid = await self._submit_url(url)

            # BƯỚC 2: Polling có bảo vệ biên cứng thời gian (Hard Wall-Clock Timeout)
            analysis_response = await self._poll_result(scan_uuid)

            # BƯỚC 3: Giải mã kết quả + tính risk score thông qua Pure Function
            result_dto = self.parse_response(analysis_response, scan_uuid, **kwargs)

            logger.info(ThreatIntelConfig.LOG_REQUEST_SUCCESS, self.PROVIDER_NAME)
            return result_dto

        except ProviderError:
            raise
        except Exception as exc:
            logger.exception(
                "[%s] Lookup orchestration unhandled crash.", self.PROVIDER_NAME
            )
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Lookup orchestration failed unexpectedly: {exc}",
                status_code=500,
                raw_error_type="UnhandledException",
            ) from exc

    # 3. _submit_url()
    async def _submit_url(self, url: str) -> str:
        """Send the URL to the URLScan submission endpoint."""
        endpoint = f"{self._base_url}{self._submit_url_path}"
        payload = {"url": url, "visibility": "public"}

        response = await self._safe_request(
            method="POST",
            url=endpoint,
            json=payload,
            headers=self._get_minimal_auth_headers(),
        )

        data = self._validate_and_extract_json(response)
        task = data.get("task", {})
        uuid_val = data.get("uuid") or (
            task.get("uuid") if isinstance(task, dict) else None
        )

        if not uuid_val:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Schema validation error: Missing UUID identifier in submission response body",
                status_code=422,
                raw_error_type="MissingUUID",
            )
        return str(uuid_val)

    # ------------------------------------------------------------------ #
    # 4. _poll_result() - Hard Boundary Safe Polling Implementation
    # ------------------------------------------------------------------ #
    async def _poll_result(self, scan_uuid: str) -> httpx.Response:
        """Poll the result endpoint with progressive backoff and strict wall-clock limits."""
        consecutive_404_count = 0
        current_backoff_multiplier = 1.0
        attempt = 1

        start_time = time.monotonic()
        deadline = start_time + self._max_poll_time

        while time.monotonic() < deadline and attempt <= self._max_poll_attempts:
            await self._sleep_with_adaptive_backoff(attempt, current_backoff_multiplier)
            attempt += 1

            response = await self._get_result(scan_uuid)

            # Phòng thủ chủ động lỗi HTTP 429 (Rate Limit) từ phía Upstream API
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    current_backoff_multiplier = (
                        float(retry_after) / self._poll_interval
                    )
                else:
                    current_backoff_multiplier *= (
                        2.0  # Phạt lũy tiến nhân đôi thời gian ngủ
                    )
                logger.warning(
                    "[%s] Rate limit hit (429) during polling. Backoff factor increased.",
                    self.PROVIDER_NAME,
                )
                continue

            # Kiểm soát bẫy Blind Retry mã lỗi HTTP 404
            if response.status_code == 404:
                consecutive_404_count += 1
                if consecutive_404_count > self.MAX_CONSECUTIVE_404:
                    raise ProviderError(
                        provider=self.PROVIDER_NAME,
                        message=f"Job validation failed. Resource consistently 404 for {consecutive_404_count} checks. Invalid or expired job.",
                        status_code=404,
                        raw_error_type="JobNotFoundExpired",
                    )
                continue

            consecutive_404_count = 0  # Trúng kết quả hợp lệ -> Reset bộ đếm lập tức
            current_backoff_multiplier = max(
                1.0, current_backoff_multiplier * 0.5
            )  # Hạ nhiệt hình phạt

            if response.status_code != 200:
                raise ProviderError(
                    provider=self.PROVIDER_NAME,
                    message=f"Upstream API gateway failure. Server returned status code {response.status_code}",
                    status_code=response.status_code,
                    raw_error_type="GatewayError",
                )

            data = self._validate_and_extract_json(response)
            status = self._extract_status_from_payload(data)

            if status == "done":
                return response
            elif status in ("pending", "processing"):
                continue
            elif status == "failed":
                raise ProviderError(
                    provider=self.PROVIDER_NAME,
                    message="Sandbox failure error: Remote execution cluster explicitly marked this scan as FAILED",
                    status_code=502,
                    raw_error_type="RemoteSandboxCrash",
                )

        raise ProviderError(
            provider=self.PROVIDER_NAME,
            message=f"Polling lifecycle expired. Hard wall-clock timeout breached after {self._max_poll_time}s hoặc vượt quá giới hạn lượt thử.",
            status_code=408,
            raw_error_type="PollingTimeoutExceeded",
        )

    # 5. Network & Transport Helpers
    async def _get_result(self, scan_uuid: str) -> httpx.Response:
        """Call GET result endpoint using clean transport encapsulation."""
        endpoint = f"{self._base_url}{self._result_url_path}".replace(
            "{uuid}", scan_uuid
        )
        return await self._safe_request(
            method="GET",
            url=endpoint,
            intercept_429=False,  # Nhả cờ để tầng poll tự bắt mã 429 adaptive
            headers=self._get_minimal_auth_headers(),
        )

    def _get_minimal_auth_headers(self) -> dict[str, str]:
        return {"API-Key": self._api_key, "Accept": "application/json"}

    async def _sleep_with_adaptive_backoff(
        self, attempt: int, multiplier: float
    ) -> None:
        """Calculates exponential backoff delay with full randomized jitter and penalty multiplier."""
        calculated_backoff = self._poll_interval * (1.4 ** (attempt - 1)) * multiplier
        actual_backoff = min(60.0, calculated_backoff)
        jittered_sleep = random.uniform(0.5 * self._poll_interval, actual_backoff)
        await asyncio.sleep(jittered_sleep)

    # 6. parse_response() - PURE FUNCTION
    def parse_response(
        self, response: httpx.Response, scan_uuid: str, **kwargs: Any
    ) -> URLScanAnalysis:

        data = self._validate_and_extract_json(response)

        if "verdicts" not in data:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Parser resilience crash: Integrity check failed. Struct does not match standard URLScan schemas",
                status_code=502,
                raw_error_type="InvalidResultSchema",
            )

        # --- Tầng 1: Basic extraction (giữ nguyên logic gốc) ---
        metadata = self._extract_metadata(data)
        page_data = self._extract_page_data(data)
        network_data = self._extract_network_data(data)
        security_signals = self._extract_security_signals(data)
        dom_metrics = self._extract_dom_metrics(data)

        # --- Tầng 2: Advanced fraud-signal extraction (bổ sung mới) ---
        network_graph = self._extract_network_graph(data)
        form_signals = self._extract_form_signals(data)
        hosting_intel = self._extract_hosting_intel(data)
        tech_stack = self._extract_tech_stack(data)

        # --- Tầng 3: Reasoning Engine / risk scoring (bổ sung mới) ---
        risk_scores = self._calculate_risk_scores(
            urlscan_score=security_signals.get("score", 0),
            redirect_count=network_data.get("redirects_count", 0),
            network_graph=network_graph,
            form_signals=form_signals,
            hosting_intel=hosting_intel,
        )

        return URLScanAnalysis(
            # Basic fields (giữ nguyên như bản gốc)
            screenshot_url=page_data.get("screenshot_url"),
            dom_size=dom_metrics.get("dom_size", 0),
            redirect_count=network_data.get("redirects_count", 0),
            external_links=network_data.get("external_links", []),
            ip_address=metadata.get("ip"),
            country=metadata.get("country"),
            malicious_score=security_signals.get("score", 0),
            tags=security_signals.get("phishing_tags", []),
            scan_id=scan_uuid,
            # Advanced fraud-signal fields (mới bổ sung)
            form_signals=form_signals,
            hosting_intel=hosting_intel,
            tech_stack=tech_stack,
            network_risk_score=risk_scores["network_risk"],
            form_risk_score=risk_scores["form_risk"],
            hosting_risk_score=risk_scores["hosting_risk"],
            urlscan_global_score=risk_scores["urlscan_global_score"],
            final_local_score=risk_scores["final_local_score"],
        )

    # 7. Tầng Xác Thực Dữ Liệu Object (Business Integrity Checks)
    def _validate_and_extract_json(self, response: httpx.Response) -> dict[str, Any]:
        """Unified business data validation pipeline for internal payloads."""
        try:
            data = response.json()
        except Exception as exc:
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"Malformed JSON token package payload received: {exc}",
                status_code=422,
                raw_error_type="MalformedJSON",
            ) from exc

        if not isinstance(data, dict):
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message="Schema integrity violation: Target JSON root is not an object model",
                status_code=502,
                raw_error_type="InvalidJSONStructure",
            )

        if "error" in data:
            err = data["error"]
            msg = (
                err.get("message", "API business error")
                if isinstance(err, dict)
                else str(err)
            )
            code = (
                err.get("code", response.status_code)
                if isinstance(err, dict)
                else response.status_code
            )
            raise ProviderError(
                provider=self.PROVIDER_NAME,
                message=f"URLScan API Internal Business Error: {msg}",
                status_code=code,
                raw_error_type="UpstreamBusinessError",
            )

        return data

    # 8. Tầng Hàm Con Trích Xuất An Toàn Dữ Liệu (Defensive Extractors)
    def _extract_status_from_payload(self, data: dict[str, Any]) -> str:
        """Đồng nhất Source of Truth cho Trạng thái xử lý dựa vào trường status gốc."""
        if "verdicts" in data or "lists" in data:
            return "done"

        status = data.get("status")
        if status:
            return str(status).strip().lower()

        task = data.get("task", {})
        if isinstance(task, dict) and "state" in task:
            return str(task.get("state")).strip().lower()

        return "pending"

    def _extract_metadata(self, data: dict[str, Any]) -> dict[str, Any]:
        page = data.get("page", {})
        return {
            "country": page.get("country") if isinstance(page, dict) else None,
            "ip": page.get("ip") if isinstance(page, dict) else None,
        }

    def _extract_page_data(self, data: dict[str, Any]) -> dict[str, Any]:
        task = data.get("task", {})
        valid_screenshot = None
        if isinstance(task, dict):
            screenshot_url = task.get("screenshotURL")
            if isinstance(screenshot_url, str) and screenshot_url.startswith("http"):
                valid_screenshot = screenshot_url
        return {"screenshot_url": valid_screenshot}

    def _extract_network_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extracts hypermedia paths safely with defensive bounds and strict JSON mapping checks."""
        data_block = data.get("data", {})
        raw_requests = (
            data_block.get("requests", []) if isinstance(data_block, dict) else []
        )
        redirects = (
            data_block.get("redirects", []) if isinstance(data_block, dict) else []
        )

        lists_block = data.get("lists", {})
        urls = lists_block.get("urls", []) if isinstance(lists_block, dict) else []

        cleaned_links = []
        if isinstance(urls, list):
            for u in urls[: ThreatIntelConfig.URLSCAN_MAX_NETWORK_REQUESTS_TO_PARSE]:
                if isinstance(u, str) and u.startswith(("http://", "https://")):
                    cleaned_links.append(u)

        redirects_count = len(redirects) if isinstance(redirects, list) else 0
        if redirects_count == 0 and isinstance(raw_requests, list):
            for req in raw_requests[
                : ThreatIntelConfig.URLSCAN_MAX_NETWORK_REQUESTS_TO_PARSE
            ]:
                if not isinstance(req, dict):
                    continue
                req_inner = req.get("response", {})
                if isinstance(req_inner, dict):
                    status = req_inner.get("status", 200)
                    if status in (301, 302, 303, 307, 308):
                        redirects_count += 1

        return {"external_links": cleaned_links, "redirects_count": redirects_count}

    def _extract_security_signals(self, data: dict[str, Any]) -> dict[str, Any]:
        verdicts = data.get("verdicts", {})
        overall = verdicts.get("overall", {}) if isinstance(verdicts, dict) else {}

        cleaned_tags = []
        if isinstance(overall, dict):
            tags = overall.get("tags", [])
            if isinstance(tags, list):
                cleaned_tags = sorted(list({str(t) for t in tags if t is not None}))

        return {
            "phishing_tags": cleaned_tags,
            "score": overall.get("score", 0) if isinstance(overall, dict) else 0,
        }

    def _extract_dom_metrics(self, data: dict[str, Any]) -> dict[str, Any]:
        page = data.get("page", {})
        task = data.get("task", {})
        dom_size = 0
        if isinstance(page, dict) and page.get("domSizeBytes"):
            dom_size = int(page.get("domSizeBytes") or 0)
        elif isinstance(task, dict) and task.get("domSizeBytes"):
            dom_size = int(task.get("domSizeBytes") or 0)
        return {"dom_size": dom_size}

    # 9. Advanced Fraud-Signal Extractors (bổ sung từ bản cải tiến)
    def _extract_network_graph(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Bóc tách sơ đồ mạng và chuỗi hành vi gọi script ngầm.
        VÁ LỖI: Sửa cấu trúc truy cập Schema chuẩn của URLScan API.
        """
        data_block = data.get("data", {})
        requests = (
            data_block.get("requests", []) if isinstance(data_block, dict) else []
        )
        if not isinstance(requests, list):
            return []

        graph: list[dict[str, Any]] = []
        for r in requests[: ThreatIntelConfig.URLSCAN_MAX_NETWORK_REQUESTS_TO_PARSE]:
            if not isinstance(r, dict):
                continue

            # SCHEMA SỬA ĐỔI: r["request"] chứa trực tiếp url và method
            req_block = (
                r.get("request", {}) if isinstance(r.get("request"), dict) else {}
            )
            resp_block = (
                r.get("response", {}) if isinstance(r.get("response"), dict) else {}
            )

            req_url = req_block.get(
                "url", ""
            )  # SỬA TẠI ĐÂY: Lấy trực tiếp url từ req_block
            if not isinstance(req_url, str):
                req_url = ""

            # Lấy status code phản hồi từ response block chuẩn
            resp_inner = (
                resp_block.get("response", {})
                if isinstance(resp_block.get("response"), dict)
                else {}
            )
            status = resp_inner.get("status") or resp_block.get("status")

            graph.append(
                {
                    "url": req_url,
                    "type": r.get("type"),
                    "initiator": r.get("initiator"),
                    "status": status,
                    "domain": urlparse(req_url).netloc.lower() if req_url else "",
                }
            )
        return graph

    def _extract_form_signals(self, data: dict[str, Any]) -> dict[str, bool | None]:
        """Phẫu thuật mã DOM để săn tìm bẫy đánh cắp thông tin.
        NÂNG CẤP: Phân biệt rõ ràng giữa "Không có Form" và "Mất dữ liệu DOM" để chống lọt lưới.
        """
        data_block = data.get("data", {})

        # Source of Truth chuẩn của URLScan là data.html
        dom = data.get("dom") or (
            data_block.get("html") if isinstance(data_block, dict) else None
        )

        if dom is None:
            # Nếu không thể lấy được DOM, gắn cờ None để Reasoning Engine biết đường xử lý
            return {
                "has_password_field": None,
                "has_login_form": None,
                "has_payment_keywords": None,
                "is_dom_missing": True,
            }

        dom_lower = str(dom).lower()
        return {
            "has_password_field": 'type="password"' in dom_lower
            or "type='password'" in dom_lower,
            "has_login_form": any(
                k in dom_lower
                for k in ["login", "signin", "đăng nhập", "credential", "mật khẩu"]
            ),
            "has_payment_keywords": any(
                k in dom_lower
                for k in ["card", "cvv", "bank", "otp", "credit", "thẻ tín dụng"]
            ),
            "is_dom_missing": False,
        }

    def _extract_hosting_intel(self, data: dict[str, Any]) -> dict[str, Any]:
        """Thu thập tình báo hạ tầng server."""
        page = data.get("page", {})
        if not isinstance(page, dict):
            page = {}
        return {
            "asn": page.get("asn"),
            "asn_name": page.get("asnname"),
            "country": page.get("country"),
            "server": page.get("server"),  # Ví dụ: nginx, Apache
        }

    def _extract_tech_stack(self, data: dict[str, Any]) -> list[str]:
        """Nhận diện vân tay công nghệ (fake checkout / SPA giả mạo, v.v.)."""
        meta = data.get("meta", {})
        if not isinstance(meta, dict):
            return []
        processors = meta.get("processors", {})
        wappalyzer = (
            processors.get("wappalyzer", {}) if isinstance(processors, dict) else {}
        )
        if isinstance(wappalyzer, dict):
            apps = wappalyzer.get("app", [])
            if isinstance(apps, list):
                return [
                    item.get("name")
                    for item in apps
                    if isinstance(item, dict) and "name" in item
                ]
        return []

    # 10. Reasoning Engine - Local Weighted Risk Score
    def _calculate_risk_scores(
        self,
        urlscan_score: float,
        redirect_count: int,
        network_graph: list[dict[str, Any]],
        form_signals: dict[str, any],
        hosting_intel: dict[str, Any],
    ) -> dict[str, float]:
        """Tính toán và áp trọng số rủi ro nội bộ, bảo vệ nghiêm ngặt chống bypass."""

        # 1. Rủi ro Form (Xử lý thông minh nếu DOM bị mất)
        form_risk = 0.0
        if form_signals.get("is_dom_missing"):
            # Nếu mất dữ liệu DOM, đặt mức rủi ro mặc định (Sự nghi ngờ trung lập) thay vì cho bằng 0
            form_risk = 0.2
        else:
            if form_signals.get("has_password_field"):
                form_risk += 0.5
            if form_signals.get("has_login_form"):
                form_risk += 0.3
            if form_signals.get("has_payment_keywords"):
                form_risk += 0.2
            form_risk = min(1.0, form_risk)

        # 2. Rủi ro mạng (Vá lỗi bypass chuỗi TLD lồng nhau)
        network_risk = 0.3 if redirect_count > 2 else 0.0

        for g in network_graph:
            domain = g.get("domain", "")
            # SỬA TẠI ĐÂY: Bảo vệ chống kịch bản hacker lừa đảo dùng subdomain lồng đuôi rác
            if any(
                domain.endswith(tld) or f"{tld}." in domain for tld in self.RISKY_TLDS
            ):
                network_risk += 0.5
                break  # Đã dính cờ rác -> Ngắt loop ngay để tối ưu hiệu năng
        network_risk = min(1.0, network_risk)

        # 3. Rủi ro hạ tầng
        hosting_risk = (
            0.8 if str(hosting_intel.get("asn")) in self.HIGH_RISK_ASNS else 0.1
        )

        # 4. Chuẩn hóa điểm phán quyết global
        urlscan_global_score = (urlscan_score or 0) / 100.0

        # 5. Công thức trọng số phán quyết nội bộ
        final_local_score = (
            form_risk * 0.4
            + network_risk * 0.2
            + hosting_risk * 0.1
            + urlscan_global_score * 0.3
        )

        return {
            "form_risk": form_risk,
            "network_risk": network_risk,
            "hosting_risk": hosting_risk,
            "urlscan_global_score": urlscan_global_score,
            "final_local_score": min(1.0, final_local_score),
        }
