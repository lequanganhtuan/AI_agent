import pytest
import asyncio
from unittest.mock import patch

from src.core.security.provider_limiter import (
    TokenBucket,
    CircuitBreaker,
    CircuitBreakerState,
    ProviderLimiterCoordinator,
)

@pytest.mark.anyio
async def test_token_bucket_refill_and_consume():
    # 2 tokens capacity, refills at 1 token/second
    bucket = TokenBucket(rate=1.0, capacity=2.0)
    
    # Consume 2 tokens -> allowed
    assert await bucket.consume() is True
    assert await bucket.consume() is True
    # Consume 3rd token -> blocked
    assert await bucket.consume() is False
    
    # Mock elapsed time by 1.1s
    with patch("time.monotonic") as mock_time:
        mock_time.return_value = bucket.last_update + 1.1
        # Now 1 token should be refilled
        assert await bucket.consume() is True
        assert await bucket.consume() is False

@pytest.mark.anyio
async def test_circuit_breaker_transitions():
    # Open after 2 failures, cooldown 5 seconds
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=5.0)
    
    # Initially CLOSED
    assert breaker.state == CircuitBreakerState.CLOSED
    assert await breaker.can_execute() is True
    
    # 1st failure -> still CLOSED
    await breaker.record_failure("TestProvider")
    assert breaker.state == CircuitBreakerState.CLOSED
    assert await breaker.can_execute() is True
    
    # 2nd failure -> transitions to OPEN
    await breaker.record_failure("TestProvider")
    assert breaker.state == CircuitBreakerState.OPEN
    assert await breaker.can_execute() is False
    
    # Mock elapsed time past cooldown (6 seconds)
    with patch("time.monotonic") as mock_time:
        mock_time.return_value = breaker.last_state_change + 6.0
        
        # Checking execution triggers HALF_OPEN
        assert await breaker.can_execute() is True
        assert breaker.state == CircuitBreakerState.HALF_OPEN
        assert breaker.in_flight_probes == 1
        
        # Concurrent check during active probe should be blocked
        assert await breaker.can_execute() is False
        
        # Test success in HALF_OPEN -> closes circuit and resets in_flight_probes
        await breaker.record_success("TestProvider")
        assert breaker.state == CircuitBreakerState.CLOSED
        assert breaker.in_flight_probes == 0
        assert await breaker.can_execute() is True

@pytest.mark.anyio
async def test_provider_limiter_coordinator():
    # Test through the global coordinator methods for VirusTotal
    coordinator = ProviderLimiterCoordinator()
    
    # Exceed VT token bucket (limit 4)
    assert await coordinator.before_execute("VirusTotal") is True
    assert await coordinator.before_execute("VirusTotal") is True
    assert await coordinator.before_execute("VirusTotal") is True
    assert await coordinator.before_execute("VirusTotal") is True
    # 5th call is blocked
    assert await coordinator.before_execute("VirusTotal") is False
    
    # Test circuit breaker opening via coordinator
    coordinator_cb = ProviderLimiterCoordinator()
    await coordinator_cb.after_execute("VirusTotal", success=False)
    await coordinator_cb.after_execute("VirusTotal", success=False)
    await coordinator_cb.after_execute("VirusTotal", success=False)
    
    # VT circuit is open, should be blocked immediately
    assert await coordinator_cb.before_execute("VirusTotal") is False

@pytest.mark.anyio
async def test_critical_provider_and_error_policy():
    coordinator = ProviderLimiterCoordinator()
    
    # 1. Gemini breaker must be critical
    assert "Gemini" in coordinator.breakers
    assert coordinator.breakers["Gemini"].is_critical is True
    assert coordinator.breakers["VirusTotal"].is_critical is False
    
    # 2. Test is_circuit_open helper
    assert await coordinator.is_circuit_open("Gemini") is False
    await coordinator.after_execute("Gemini", success=False)
    await coordinator.after_execute("Gemini", success=False)
    await coordinator.after_execute("Gemini", success=False)
    assert await coordinator.is_circuit_open("Gemini") is True
    
    # 3. Test ErrorPolicy treats NodeName.AI as fatal (ErrorAction.STOP)
    from src.agents.error.policy import ErrorPolicy
    from src.agents.state.enums import NodeName
    from src.agents.error.strategy import ErrorAction
    
    policy = ErrorPolicy()
    decision = policy.handle("LLM Rate Limit Error", NodeName.AI, retry_count=3, retryable=False)
    assert decision.action == ErrorAction.STOP
    assert decision.error_type == "RateLimitError"
