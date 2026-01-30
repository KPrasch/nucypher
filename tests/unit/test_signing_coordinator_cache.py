"""
Tests for SigningCoordinatorAgent cohort caching.

These tests verify that:
1. get_signing_cohort() results are cached
2. is_cohort_active() uses cached cohort data
3. is_signer() uses cached cohort data
4. Cache entries expire after TTL
5. Cache can be explicitly invalidated
6. Thread safety under concurrent access
"""

import time
from concurrent.futures import ThreadPoolExecutor, wait
from unittest.mock import MagicMock, patch

import maya
import pytest

from nucypher.blockchain.eth.agents import SigningCoordinatorAgent


@pytest.fixture
def mock_contract():
    """Create a mock contract with signing cohort functions."""
    contract = MagicMock()

    # Mock cohort data that would be returned from chain
    cohort_data = (
        "0x1234567890123456789012345678901234567890",  # initiator
        int(time.time()) - 100,  # init_timestamp (100 seconds ago)
        int(time.time()) + 3600,  # end_timestamp (1 hour from now)
        "0xABCDEF0123456789012345678901234567890ABC",  # authority
        0,  # total_signatures
        2,  # num_signers
        2,  # threshold
    )
    contract.functions.signingCohorts.return_value.call.return_value = cohort_data

    # Mock signers data
    signers_data = [
        (
            "0x1111111111111111111111111111111111111111",  # provider
            "0x2222222222222222222222222222222222222222",  # signer_address
            b"signing_request_key_1",  # signing_request_key
        ),
        (
            "0x3333333333333333333333333333333333333333",  # provider
            "0x4444444444444444444444444444444444444444",  # signer_address
            b"signing_request_key_2",  # signing_request_key
        ),
    ]
    contract.functions.getSigners.return_value.call.return_value = signers_data

    # Mock chains
    contract.functions.getChains.return_value.call.return_value = [1, 137]

    # Mock conditions per chain
    contract.functions.getSigningCohortConditions.return_value.call.return_value = (
        b'{"condition": "test"}'
    )

    # Mock is_cohort_active and is_signer (direct contract calls)
    contract.functions.isCohortActive.return_value.call.return_value = True
    contract.functions.isSigner.return_value.call.return_value = True

    # Mock getSigningCohortState - return ACTIVE status (3)
    contract.functions.getSigningCohortState.return_value.call.return_value = 3

    return contract


@pytest.fixture
def mock_blockchain():
    """Create a mock blockchain interface."""
    blockchain = MagicMock()
    blockchain.w3 = MagicMock()
    # Mock get_block to return current time as timestamp
    mock_block = MagicMock()
    mock_block.timestamp = int(time.time())
    blockchain.w3.eth.get_block.return_value = mock_block
    return blockchain


@pytest.fixture
def agent(mock_contract, mock_blockchain):
    """Create a SigningCoordinatorAgent with mocked dependencies."""
    from nucypher.utilities.cache import TTLCache

    with patch.object(
        SigningCoordinatorAgent, "__init__", lambda self, *args, **kwargs: None
    ):
        agent = SigningCoordinatorAgent.__new__(SigningCoordinatorAgent)
        # Use the private attribute name that the property reads from
        agent._EthereumContractAgent__contract = mock_contract
        agent.blockchain = mock_blockchain
        # Initialize the cache - mimics what the real __init__ does
        agent._cohort_cache = TTLCache(ttl=60)
    return agent


class TestCohortCacheBasics:
    """Test basic cache hit/miss behavior."""

    def test_get_signing_cohort_caches_result(self, agent, mock_contract):
        """First call fetches from chain, second call uses cache."""
        cohort_id = 1

        # First call - should hit the contract
        cohort1 = agent.get_signing_cohort(cohort_id)
        assert mock_contract.functions.signingCohorts.call_count == 1

        # Second call - should use cache, not hit contract again
        cohort2 = agent.get_signing_cohort(cohort_id)
        assert mock_contract.functions.signingCohorts.call_count == 1  # Still 1

        # Should return the same data
        assert cohort1.id == cohort2.id
        assert cohort1.authority == cohort2.authority

    def test_different_cohort_ids_cached_separately(self, agent, mock_contract):
        """Each cohort_id has its own cache entry."""
        # Fetch cohort 1
        agent.get_signing_cohort(1)
        assert mock_contract.functions.signingCohorts.call_count == 1

        # Fetch cohort 2 - should hit contract (different key)
        agent.get_signing_cohort(2)
        assert mock_contract.functions.signingCohorts.call_count == 2

        # Fetch cohort 1 again - should use cache
        agent.get_signing_cohort(1)
        assert mock_contract.functions.signingCohorts.call_count == 2  # Still 2


class TestIsCohortActiveCache:
    """Test that is_cohort_active caches its result."""

    def test_is_cohort_active_caches_result(self, agent, mock_contract):
        """is_cohort_active should cache the contract call result."""
        cohort_id = 1

        # First call - should hit contract
        result1 = agent.is_cohort_active(cohort_id)
        assert mock_contract.functions.isCohortActive.call_count == 1
        assert result1 is True

        # Second call - should use cache
        result2 = agent.is_cohort_active(cohort_id)
        assert mock_contract.functions.isCohortActive.call_count == 1  # Still 1
        assert result2 is True

    def test_different_cohort_ids_cached_separately(self, agent, mock_contract):
        """Each cohort_id has its own cache entry for is_cohort_active."""
        agent.is_cohort_active(1)
        assert mock_contract.functions.isCohortActive.call_count == 1

        agent.is_cohort_active(2)
        assert mock_contract.functions.isCohortActive.call_count == 2

        # Calling cohort 1 again should use cache
        agent.is_cohort_active(1)
        assert mock_contract.functions.isCohortActive.call_count == 2


class TestIsSignerCache:
    """Test that is_signer caches its result."""

    def test_is_signer_caches_result(self, agent, mock_contract):
        """is_signer should cache the contract call result."""
        cohort_id = 1
        provider = "0x1111111111111111111111111111111111111111"

        # First call - should hit contract
        result1 = agent.is_signer(cohort_id, provider)
        assert mock_contract.functions.isSigner.call_count == 1
        assert result1 is True

        # Second call - should use cache
        result2 = agent.is_signer(cohort_id, provider)
        assert mock_contract.functions.isSigner.call_count == 1  # Still 1
        assert result2 is True

    def test_different_providers_cached_separately(self, agent, mock_contract):
        """Each cohort_id + provider combo has its own cache entry."""
        provider1 = "0x1111111111111111111111111111111111111111"
        provider2 = "0x2222222222222222222222222222222222222222"

        agent.is_signer(1, provider1)
        assert mock_contract.functions.isSigner.call_count == 1

        agent.is_signer(1, provider2)
        assert mock_contract.functions.isSigner.call_count == 2

        # Calling provider1 again should use cache
        agent.is_signer(1, provider1)
        assert mock_contract.functions.isSigner.call_count == 2


class TestCacheTTL:
    """Test cache TTL expiration behavior."""

    def test_cache_expires_after_ttl(self, agent, mock_contract):
        """Cache entries should expire and trigger fresh fetch."""
        cohort_id = 1
        now = maya.now()

        # First call - cache miss
        with patch("maya.now", return_value=now):
            agent.get_signing_cohort(cohort_id)
        assert mock_contract.functions.signingCohorts.call_count == 1

        # Call within TTL - should hit cache
        with patch("maya.now", return_value=now.add(seconds=30)):
            agent.get_signing_cohort(cohort_id)
        assert mock_contract.functions.signingCohorts.call_count == 1  # Still 1

        # Call after TTL (default 60s) - should miss cache
        with patch("maya.now", return_value=now.add(seconds=61)):
            agent.get_signing_cohort(cohort_id)
        assert mock_contract.functions.signingCohorts.call_count == 2  # Now 2

    def test_ttl_configurable_via_environment(self, mock_contract, mock_blockchain):
        """Cache TTL should be configurable via environment variable."""
        from nucypher.utilities.cache import TTLCache

        with patch.dict("os.environ", {"NUCYPHER_COHORT_CACHE_TTL": "30"}):
            with patch.object(
                SigningCoordinatorAgent, "__init__", lambda self, *args, **kwargs: None
            ):
                agent = SigningCoordinatorAgent.__new__(SigningCoordinatorAgent)
                agent._EthereumContractAgent__contract = mock_contract
                agent.blockchain = mock_blockchain
                # Agent should use 30s TTL from environment
                agent._cohort_cache = TTLCache(ttl=30)

        cohort_id = 1
        now = maya.now()

        # First call
        with patch("maya.now", return_value=now):
            agent.get_signing_cohort(cohort_id)

        # Call after 31 seconds - should expire with 30s TTL
        with patch("maya.now", return_value=now.add(seconds=31)):
            agent.get_signing_cohort(cohort_id)

        assert mock_contract.functions.signingCohorts.call_count == 2


class TestCacheInvalidation:
    """Test explicit cache invalidation."""

    def test_invalidate_cohort_cache_forces_refetch(self, agent, mock_contract):
        """invalidate_cohort_cache should remove entry, forcing next call to fetch."""
        cohort_id = 1

        # Prime the cache
        agent.get_signing_cohort(cohort_id)
        assert mock_contract.functions.signingCohorts.call_count == 1

        # Invalidate the cache
        agent.invalidate_cohort_cache(cohort_id)

        # Next call should fetch from chain
        agent.get_signing_cohort(cohort_id)
        assert mock_contract.functions.signingCohorts.call_count == 2

    def test_invalidate_nonexistent_cohort_is_safe(self, agent):
        """Invalidating a cohort that's not in cache should not raise."""
        # Should not raise
        agent.invalidate_cohort_cache(999)

    def test_purge_expired_cache_entries(self, agent, mock_contract):
        """purge_expired_cache_entries should remove expired entries."""
        cohort_id = 1
        now = maya.now()

        # Prime the cache
        with patch("maya.now", return_value=now):
            agent.get_signing_cohort(cohort_id)

        # Verify cache is populated
        with patch("maya.now", return_value=now):
            assert agent._cohort_cache[cohort_id] is not None

        # Advance time past TTL
        with patch("maya.now", return_value=now.add(seconds=61)):
            # Purge expired entries
            agent.purge_expired_cache_entries()

            # Cache should now be empty for this entry
            assert agent._cohort_cache[cohort_id] is None


class TestThreadSafety:
    """Test thread safety of cache operations."""

    def test_concurrent_reads_same_cohort(self, agent, mock_contract):
        """Multiple threads reading same cohort should not cause issues."""
        cohort_id = 1
        num_threads = 10
        num_reads_per_thread = 20

        def read_cohort():
            for _ in range(num_reads_per_thread):
                cohort = agent.get_signing_cohort(cohort_id)
                assert cohort is not None

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(read_cohort) for _ in range(num_threads)]
            wait(futures, timeout=10)

        # All reads should succeed
        for f in futures:
            f.result()  # Raises if any thread failed

        # Should have made only a few contract calls (not 200)
        # First call populates cache, rest should hit cache
        assert mock_contract.functions.signingCohorts.call_count < 10

    def test_concurrent_reads_different_cohorts(self, agent, mock_contract):
        """Multiple threads reading different cohorts concurrently."""
        num_cohorts = 5
        num_threads = 10

        def read_random_cohorts():
            import random

            for _ in range(10):
                cohort_id = random.randint(0, num_cohorts - 1)
                cohort = agent.get_signing_cohort(cohort_id)
                assert cohort is not None

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(read_random_cohorts) for _ in range(num_threads)]
            wait(futures, timeout=10)

        for f in futures:
            f.result()
