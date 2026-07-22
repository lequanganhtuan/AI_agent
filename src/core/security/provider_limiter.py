import time
import asyncio
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class TokenBucket:
    """Thread-safe Token Bucket for rate limiting upstream providers."""
    def __init__(self, rate: float, capacity: float):
        """
        rate: Number of tokens added per second.
        capacity: Maximum tokens in the bucket.
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            # Refill tokens based on elapsed time
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

class CircuitBreakerState:
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"

class CircuitBreaker:
    """Circuit Breaker for isolating failing upstream providers."""
    def __init__(self, failure_threshold: int = 3, recovery_timeout: float = 300.0, is_critical: bool = False):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.is_critical = is_critical
        self.state = CircuitBreakerState.CLOSED
        self.failures = 0
        self.in_flight_probes = 0
        self.last_state_change = time.monotonic()
        self._lock = asyncio.Lock()

    async def can_execute(self) -> bool:
        async with self._lock:
            if self.state == CircuitBreakerState.CLOSED:
                return True
            
            now = time.monotonic()
            if self.state == CircuitBreakerState.OPEN:
                # If cooldown period has passed, transition to HALF_OPEN to test provider health
                if now - self.last_state_change > self.recovery_timeout:
                    self.state = CircuitBreakerState.HALF_OPEN
                    self.failures = 0
                    self.last_state_change = now
                    self.in_flight_probes = 1
                    logger.info(f"[CircuitBreaker] Cooldown elapsed. State changed to HALF_OPEN to probe provider.")
                    return True
                return False
            
            if self.state == CircuitBreakerState.HALF_OPEN:
                # Guarantee only a single probe is in flight at a time
                if self.in_flight_probes > 0:
                    return False
                self.in_flight_probes = 1
                return True
            
            return True

    async def record_success(self, provider_name: str):
        async with self._lock:
            self.failures = 0
            self.in_flight_probes = 0
            if self.state != CircuitBreakerState.CLOSED:
                logger.info(f"[CircuitBreaker] Provider '{provider_name}' request succeeded. Circuit CLOSED.")
                self.state = CircuitBreakerState.CLOSED
                self.last_state_change = time.monotonic()

    async def record_failure(self, provider_name: str):
        async with self._lock:
            self.failures += 1
            self.in_flight_probes = 0
            now = time.monotonic()
            
            # If a trial probe fails in HALF_OPEN, or normal threshold is reached
            if self.state == CircuitBreakerState.HALF_OPEN or self.failures >= self.failure_threshold:
                if self.state != CircuitBreakerState.OPEN:
                    logger.error(
                        f"[CircuitBreaker] Provider '{provider_name}' reached failure threshold ({self.failures}/{self.failure_threshold}) or failed probe. Circuit OPENED. Cooldown: {self.recovery_timeout}s"
                    )
                    self.state = CircuitBreakerState.OPEN
                    self.last_state_change = now

class ProviderLimiterCoordinator:
    """Coordinates Token Buckets and Circuit Breakers across all upstream providers."""
    def __init__(self):
        # Configuration matches real-world limits:
        # - VirusTotal: 4 requests / minute = 4/60 tokens/sec. Capacity 4.
        # - AbuseIPDB: 10 requests / minute = 10/60 tokens/sec. Capacity 10.
        # - URLScan: 10 requests / minute = 10/60 tokens/sec. Capacity 10.
        # - URLHaus: 30 requests / minute = 30/60 tokens/sec. Capacity 30.
        # - GoogleSafeBrowsing: 60 requests / minute = 60/60 tokens/sec. Capacity 60.
        # - PhishTank: 10 requests / minute = 10/60 tokens/sec. Capacity 10.
        # - Gemini: 15 requests / minute = 15/60 tokens/sec. Capacity 15.
        self.buckets: Dict[str, TokenBucket] = {
            "VirusTotal": TokenBucket(rate=4.0 / 60.0, capacity=4.0),
            "AbuseIPDB": TokenBucket(rate=10.0 / 60.0, capacity=10.0),
            "URLScan": TokenBucket(rate=10.0 / 60.0, capacity=10.0),
            "URLHaus": TokenBucket(rate=30.0 / 60.0, capacity=30.0),
            "GoogleSafeBrowsing": TokenBucket(rate=60.0 / 60.0, capacity=60.0),
            "PhishTank": TokenBucket(rate=10.0 / 60.0, capacity=10.0),
            "Gemini": TokenBucket(rate=15.0 / 60.0, capacity=15.0),
        }
        
        # 3 failures block calls for 300s (5 minutes)
        # Gemini is critical, so we flag is_critical=True
        self.breakers: Dict[str, CircuitBreaker] = {
            "VirusTotal": CircuitBreaker(failure_threshold=3, recovery_timeout=300.0),
            "AbuseIPDB": CircuitBreaker(failure_threshold=3, recovery_timeout=300.0),
            "URLScan": CircuitBreaker(failure_threshold=3, recovery_timeout=300.0),
            "URLHaus": CircuitBreaker(failure_threshold=3, recovery_timeout=300.0),
            "GoogleSafeBrowsing": CircuitBreaker(failure_threshold=3, recovery_timeout=300.0),
            "PhishTank": CircuitBreaker(failure_threshold=3, recovery_timeout=300.0),
            "Gemini": CircuitBreaker(failure_threshold=3, recovery_timeout=300.0, is_critical=True),
        }

    async def is_circuit_open(self, provider: str) -> bool:
        """Returns True if the circuit breaker for the given provider is currently OPEN."""
        breaker = self.breakers.get(provider)
        if breaker:
            return breaker.state == CircuitBreakerState.OPEN
        return False

    async def before_execute(self, provider: str) -> bool:
        """
        Check if execution is allowed based on Circuit Breaker state and Token Bucket capacity.
        Returns True if proceeding is allowed, False if throttled or isolated.
        """
        # 1. Circuit Breaker check
        breaker = self.breakers.get(provider)
        if breaker and not await breaker.can_execute():
            logger.warning(f"[ProviderLimiter] Provider '{provider}' blocked. Circuit is OPEN.")
            return False

        # 2. Token Bucket check
        bucket = self.buckets.get(provider)
        if bucket:
            if not await bucket.consume():
                logger.warning(f"[ProviderLimiter] Provider '{provider}' blocked. Token Bucket exhausted (Rate Limited).")
                return False

        return True

    async def after_execute(self, provider: str, success: bool):
        """Record the outcome of the request to trigger circuit changes if needed."""
        breaker = self.breakers.get(provider)
        if breaker:
            if success:
                await breaker.record_success(provider)
            else:
                await breaker.record_failure(provider)

# Global singleton instance
provider_limiter = ProviderLimiterCoordinator()
