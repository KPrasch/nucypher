"""
Tests for event-based cohort cache invalidation.

These tests verify that:
1. SigningRitualTracker tracks SigningCohortConditionsSet events
2. When SigningCohortConditionsSet event is received, cohort cache is invalidated
3. When SigningCohortDeployed event is received, cohort cache is invalidated
4. InitiateSigningCohort does NOT invalidate cache (new cohort, not in cache)
"""

from unittest.mock import MagicMock, patch

import pytest
from web3.datastructures import AttributeDict

from nucypher.blockchain.eth.trackers.signing import SigningRitualTracker


@pytest.fixture
def mock_signing_coordinator_agent():
    """Create a mock SigningCoordinatorAgent with cache."""
    agent = MagicMock()
    agent.contract = MagicMock()

    # Mock blockchain and web3
    agent.blockchain = MagicMock()
    agent.blockchain.w3 = MagicMock()
    agent.blockchain.w3.eth.get_block.return_value = {
        "number": 12345678,
        "timestamp": 1234567890,
    }

    # Mock events
    agent.contract.events.InitiateSigningCohort = MagicMock()
    agent.contract.events.SigningCohortDeployed = MagicMock()
    agent.contract.events.SigningCohortConditionsSet = MagicMock()

    # Mock timeout
    agent.get_timeout.return_value = 3600

    # Mock invalidate_cohort_cache
    agent.invalidate_cohort_cache = MagicMock()

    return agent


@pytest.fixture
def mock_operator(mock_signing_coordinator_agent):
    """Create a mock operator with signing coordinator agent."""
    operator = MagicMock()
    operator.signing_coordinator_agent = mock_signing_coordinator_agent
    operator.checksum_address = "0x1234567890123456789012345678901234567890"
    operator.transacting_power = MagicMock()
    operator.transacting_power.account = "0xABCDEF1234567890123456789012345678901234"
    operator.perform_post_signature = MagicMock()
    return operator


@pytest.fixture
def mock_web3():
    """Create a mock Web3 instance."""
    w3 = MagicMock()
    w3.eth.chain_id = 1
    w3.eth.get_block.return_value = {"number": 12345678, "timestamp": 1234567890}
    return w3


class TestSigningRitualTrackerEventsConfiguration:
    """Test that SigningRitualTracker is configured to track the right events."""

    def test_tracker_tracks_signing_cohort_conditions_set_event(
        self, mock_operator, mock_web3
    ):
        """SigningRitualTracker should track SigningCohortConditionsSet event."""
        with patch.object(
            SigningRitualTracker, "__init__", lambda self, *args, **kwargs: None
        ):
            tracker = SigningRitualTracker.__new__(SigningRitualTracker)

        # Verify the event is in the tracked events list
        # This test will need the actual tracker initialization to be modified
        # to include SigningCohortConditionsSet
        contract = mock_operator.signing_coordinator_agent.contract

        # This will fail until we add SigningCohortConditionsSet to tracked events
        # Checking the actual implementation after patching
        tracker = SigningRitualTracker(operator=mock_operator, persistent=False)
        assert contract.events.SigningCohortConditionsSet in tracker.events


class TestCacheInvalidationOnEvents:
    """Test that cache is invalidated when relevant events are received."""

    def test_signing_cohort_conditions_set_invalidates_cache(
        self, mock_operator, mock_signing_coordinator_agent
    ):
        """SigningCohortConditionsSet event should invalidate the cohort cache."""
        tracker = SigningRitualTracker(operator=mock_operator, persistent=False)

        # Create a mock event
        cohort_id = 42
        event = AttributeDict(
            {
                "event": "SigningCohortConditionsSet",
                "args": AttributeDict(
                    {
                        "cohortId": cohort_id,
                        "chainId": 1,
                        "conditions": b'{"new": "conditions"}',
                    }
                ),
                "blockNumber": 12345678,
            }
        )

        # Simulate receiving the event
        mock_get_block_when = MagicMock(
            return_value=MagicMock(timestamp=lambda: 1234567890)
        )
        tracker._handle_event(event, mock_get_block_when)

        # Verify cache was invalidated for this cohort
        mock_signing_coordinator_agent.invalidate_cohort_cache.assert_called_with(
            cohort_id
        )

    def test_signing_cohort_deployed_invalidates_cache(
        self, mock_operator, mock_signing_coordinator_agent
    ):
        """SigningCohortDeployed event should invalidate the cohort cache."""
        tracker = SigningRitualTracker(operator=mock_operator, persistent=False)

        # Create a mock event
        cohort_id = 42
        event = AttributeDict(
            {
                "event": "SigningCohortDeployed",
                "args": AttributeDict(
                    {
                        "cohortId": cohort_id,
                        "chainId": 1,
                    }
                ),
                "blockNumber": 12345678,
            }
        )

        # Simulate receiving the event
        mock_get_block_when = MagicMock(
            return_value=MagicMock(timestamp=lambda: 1234567890)
        )
        tracker._handle_event(event, mock_get_block_when)

        # Verify cache was invalidated for this cohort
        mock_signing_coordinator_agent.invalidate_cohort_cache.assert_called_with(
            cohort_id
        )

    def test_initiate_signing_cohort_does_not_invalidate_cache(
        self, mock_operator, mock_signing_coordinator_agent
    ):
        """InitiateSigningCohort event should NOT invalidate cache (new cohort)."""
        tracker = SigningRitualTracker(operator=mock_operator, persistent=False)

        # Create a mock event for cohort initiation
        cohort_id = 42
        event = AttributeDict(
            {
                "event": "InitiateSigningCohort",
                "args": AttributeDict(
                    {
                        "cohortId": cohort_id,
                        "chainId": 1,
                        "authority": "0xABCD",
                        "participants": [mock_operator.checksum_address],
                    }
                ),
                "blockNumber": 12345678,
            }
        )

        # Simulate receiving the event
        mock_get_block_when = MagicMock(
            return_value=MagicMock(timestamp=lambda: 1234567890)
        )
        tracker._handle_event(event, mock_get_block_when)

        # Verify cache was NOT invalidated (new cohort isn't in cache anyway)
        mock_signing_coordinator_agent.invalidate_cohort_cache.assert_not_called()


class TestCacheInvalidationIntegration:
    """Integration tests for cache invalidation flow."""

    def test_cohort_data_refreshed_after_conditions_update(
        self, mock_operator, mock_signing_coordinator_agent
    ):
        """After conditions update event, next cohort fetch should get fresh data."""
        from nucypher.utilities.cache import TTLCache

        # Set up a real cache on the agent
        mock_signing_coordinator_agent._cohort_cache = TTLCache(ttl=60)

        # Pre-populate the cache with old data
        old_cohort = MagicMock()
        old_cohort.conditions = {1: b'{"old": "conditions"}'}
        cohort_id = 42
        mock_signing_coordinator_agent._cohort_cache[cohort_id] = old_cohort

        # Make invalidate_cohort_cache actually remove from cache
        def real_invalidate(cid):
            mock_signing_coordinator_agent._cohort_cache.remove(cid)

        mock_signing_coordinator_agent.invalidate_cohort_cache = real_invalidate

        tracker = SigningRitualTracker(operator=mock_operator, persistent=False)

        # Simulate conditions update event
        event = AttributeDict(
            {
                "event": "SigningCohortConditionsSet",
                "args": AttributeDict(
                    {
                        "cohortId": cohort_id,
                        "chainId": 1,
                        "conditions": b'{"new": "conditions"}',
                    }
                ),
                "blockNumber": 12345678,
            }
        )

        mock_get_block_when = MagicMock(
            return_value=MagicMock(timestamp=lambda: 1234567890)
        )
        tracker._handle_event(event, mock_get_block_when)

        # Verify cohort was removed from cache
        assert mock_signing_coordinator_agent._cohort_cache[cohort_id] is None
