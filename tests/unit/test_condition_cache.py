import threading
import time
from unittest.mock import MagicMock

import pytest
import time_machine

from nucypher.utilities.cache import TTLCache


class ConditionCacheFixture:
    """
    Minimal harness that mirrors the caching state and _get_signing_conditions
    method that will be added to Operator. We test against this fixture so we
    don't need to instantiate the full Operator dependency tree.

    Once the implementation lands in actors.py, these tests should be updated
    to exercise the real Operator._get_signing_conditions if a lightweight
    construction path becomes available.
    """

    def __init__(self, agent, ttl: int = 2):
        self.signing_coordinator_agent = agent
        self._condition_cache = TTLCache(ttl=ttl)
        self._condition_fetch_locks: dict = {}
        self._condition_fetch_locks_lock = threading.Lock()

    def _get_signing_conditions(self, cohort_id: int, chain_id: int) -> bytes:
        """Fetch condition bytes with short-TTL cache and single-flight dedup."""
        cache_key = (cohort_id, chain_id)

        # Fast path: cache hit
        cached = self._condition_cache[cache_key]
        if cached is not None:
            return cached

        # Get or create per-key lock for single-flight dedup
        with self._condition_fetch_locks_lock:
            if cache_key not in self._condition_fetch_locks:
                self._condition_fetch_locks[cache_key] = threading.Lock()
            key_lock = self._condition_fetch_locks[cache_key]

        # Only one thread fetches; others wait then hit warm cache
        with key_lock:
            # Double-check after acquiring lock
            cached = self._condition_cache[cache_key]
            if cached is not None:
                return cached

            condition_bytes = (
                self.signing_coordinator_agent.get_signing_cohort_conditions(
                    cohort_id=cohort_id, chain_id=chain_id
                )
            )
            if condition_bytes:
                self._condition_cache[cache_key] = condition_bytes
            return condition_bytes


@pytest.fixture
def mock_agent():
    agent = MagicMock()
    agent.get_signing_cohort_conditions.return_value = (
        b'{"version": "1.0.0", "condition": {"conditionType": "time"}}'
    )
    return agent


@pytest.fixture
def cache_fixture(mock_agent):
    return ConditionCacheFixture(agent=mock_agent, ttl=2)


class TestConditionCacheHit:
    """Second call for the same key should use cache, not fetch again."""

    def test_cache_hit_avoids_rpc(self, cache_fixture, mock_agent):
        result1 = cache_fixture._get_signing_conditions(cohort_id=1, chain_id=137)
        result2 = cache_fixture._get_signing_conditions(cohort_id=1, chain_id=137)

        assert result1 == result2
        mock_agent.get_signing_cohort_conditions.assert_called_once_with(
            cohort_id=1, chain_id=137
        )


class TestConditionCacheTTLExpiry:
    """After TTL expires, a fresh fetch should occur."""

    def test_expired_entry_triggers_refetch(self, mock_agent):
        with time_machine.travel(0, tick=False) as traveller:
            fixture = ConditionCacheFixture(agent=mock_agent, ttl=2)
            fixture._get_signing_conditions(cohort_id=1, chain_id=1)
            assert mock_agent.get_signing_cohort_conditions.call_count == 1

            # Advance time past the TTL
            traveller.shift(3)

            fixture._get_signing_conditions(cohort_id=1, chain_id=1)
            assert mock_agent.get_signing_cohort_conditions.call_count == 2

    def test_within_ttl_still_cached(self, mock_agent):
        with time_machine.travel(0, tick=False) as traveller:
            fixture = ConditionCacheFixture(agent=mock_agent, ttl=15)
            fixture._get_signing_conditions(cohort_id=1, chain_id=1)

            # Advance time but stay within TTL
            traveller.shift(10)

            fixture._get_signing_conditions(cohort_id=1, chain_id=1)
            assert mock_agent.get_signing_cohort_conditions.call_count == 1


class TestConditionCacheDifferentKeys:
    """Different (cohort_id, chain_id) pairs get separate cache entries."""

    def test_different_keys_fetch_independently(self, cache_fixture, mock_agent):
        cache_fixture._get_signing_conditions(cohort_id=1, chain_id=137)
        cache_fixture._get_signing_conditions(cohort_id=1, chain_id=1)
        cache_fixture._get_signing_conditions(cohort_id=2, chain_id=137)

        assert mock_agent.get_signing_cohort_conditions.call_count == 3

    def test_same_key_after_different_key_still_cached(self, cache_fixture, mock_agent):
        cache_fixture._get_signing_conditions(cohort_id=1, chain_id=137)
        cache_fixture._get_signing_conditions(cohort_id=2, chain_id=137)
        # This should be a cache hit
        cache_fixture._get_signing_conditions(cohort_id=1, chain_id=137)

        assert mock_agent.get_signing_cohort_conditions.call_count == 2


class TestConditionCacheSingleFlight:
    """Multiple concurrent requests for the same key should result in a single RPC call."""

    def test_concurrent_requests_single_fetch(self, mock_agent):
        # Use a slower agent to widen the race window
        call_count = 0
        call_lock = threading.Lock()
        condition_bytes = (
            b'{"version": "1.0.0", "condition": {"conditionType": "time"}}'
        )

        def slow_fetch(cohort_id, chain_id):
            nonlocal call_count
            with call_lock:
                call_count += 1
            time.sleep(0.2)  # simulate RPC latency
            return condition_bytes

        mock_agent.get_signing_cohort_conditions.side_effect = slow_fetch
        fixture = ConditionCacheFixture(agent=mock_agent, ttl=10)

        num_threads = 10
        barrier = threading.Barrier(num_threads)
        results = [None] * num_threads
        errors = []

        def worker(idx):
            try:
                barrier.wait(timeout=5)
                results[idx] = fixture._get_signing_conditions(
                    cohort_id=1, chain_id=137
                )
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(i,)) for i in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Worker threads raised errors: {errors}"
        assert call_count == 1, f"Expected 1 RPC call, got {call_count}"
        assert all(r == condition_bytes for r in results)


class TestConditionCacheEmptyNotCached:
    """Empty/falsy condition bytes should not be cached."""

    def test_empty_bytes_not_cached(self, mock_agent):
        mock_agent.get_signing_cohort_conditions.return_value = b""
        fixture = ConditionCacheFixture(agent=mock_agent, ttl=10)

        result1 = fixture._get_signing_conditions(cohort_id=1, chain_id=1)
        result2 = fixture._get_signing_conditions(cohort_id=1, chain_id=1)

        assert result1 == b""
        assert result2 == b""
        assert mock_agent.get_signing_cohort_conditions.call_count == 2

    def test_none_not_cached(self, mock_agent):
        mock_agent.get_signing_cohort_conditions.return_value = None
        fixture = ConditionCacheFixture(agent=mock_agent, ttl=10)

        result1 = fixture._get_signing_conditions(cohort_id=1, chain_id=1)
        result2 = fixture._get_signing_conditions(cohort_id=1, chain_id=1)

        assert result1 is None
        assert result2 is None
        assert mock_agent.get_signing_cohort_conditions.call_count == 2


class TestConditionCacheRPCFailure:
    """RPC exceptions should propagate and not be cached."""

    def test_exception_propagates(self, mock_agent):
        mock_agent.get_signing_cohort_conditions.side_effect = ConnectionError(
            "RPC unavailable"
        )
        fixture = ConditionCacheFixture(agent=mock_agent, ttl=10)

        with pytest.raises(ConnectionError, match="RPC unavailable"):
            fixture._get_signing_conditions(cohort_id=1, chain_id=1)

    def test_exception_not_cached(self, mock_agent):
        """After a failure, the next call should retry (not serve a cached error)."""
        condition_bytes = (
            b'{"version": "1.0.0", "condition": {"conditionType": "time"}}'
        )
        mock_agent.get_signing_cohort_conditions.side_effect = [
            ConnectionError("RPC unavailable"),
            condition_bytes,
        ]
        fixture = ConditionCacheFixture(agent=mock_agent, ttl=10)

        with pytest.raises(ConnectionError):
            fixture._get_signing_conditions(cohort_id=1, chain_id=1)

        # Second call should succeed
        result = fixture._get_signing_conditions(cohort_id=1, chain_id=1)
        assert result == condition_bytes
        assert mock_agent.get_signing_cohort_conditions.call_count == 2


class TestConditionCacheSingleFlightWithFailure:
    """When the single-flight leader fails, subsequent requests should retry."""

    def test_leader_failure_allows_retry(self, mock_agent):
        condition_bytes = (
            b'{"version": "1.0.0", "condition": {"conditionType": "time"}}'
        )
        call_sequence = [ConnectionError("RPC down"), condition_bytes]
        mock_agent.get_signing_cohort_conditions.side_effect = call_sequence
        fixture = ConditionCacheFixture(agent=mock_agent, ttl=10)

        # First call fails
        with pytest.raises(ConnectionError):
            fixture._get_signing_conditions(cohort_id=1, chain_id=1)

        # Second call should retry and succeed
        result = fixture._get_signing_conditions(cohort_id=1, chain_id=1)
        assert result == condition_bytes
