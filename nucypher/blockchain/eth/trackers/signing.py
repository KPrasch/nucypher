import datetime
from typing import Callable, Optional

from web3.datastructures import AttributeDict

from nucypher.blockchain.eth.constants import NULL_ADDRESS
from nucypher.blockchain.eth.models import SigningCoordinator
from nucypher.blockchain.eth.trackers.rituals import RitualTracker


class SigningRitualTracker(RitualTracker):
    class SigningParticipationState(RitualTracker.ParticipationState):
        """
        Participation state for Signing rituals.
        """

        PREFIX = "signing-"

        def __init__(
            self,
            participating=False,
            already_posted_signature=False,
        ):
            super().__init__(participating)
            self.already_posted_signature = already_posted_signature

    # Events that should trigger cohort cache invalidation
    # Note: SigningCohortConditionsSet is intentionally excluded because conditions
    # are always fetched directly from the contract (never cached)
    _CACHE_INVALIDATION_EVENTS = {"SigningCohortDeployed"}

    def __init__(
        self,
        operator,
        persistent: bool = False,
    ):
        contract = operator.signing_coordinator_agent.contract
        actions = {
            contract.events.InitiateSigningCohort: operator.perform_post_signature,
        }
        events = [
            contract.events.InitiateSigningCohort,
            contract.events.SigningCohortDeployed,
        ]

        self.signing_coordinator_agent = operator.signing_coordinator_agent

        super().__init__(
            operator=operator,
            web3=operator.signing_coordinator_agent.blockchain.w3,
            contract=contract,
            events=events,
            actions=actions,
            persistent=persistent,
            timeout=self.signing_coordinator_agent.get_timeout(),
        )

    def _get_identifier(self, event: AttributeDict) -> str:
        return f"{self.SigningParticipationState.PREFIX}{event.args.cohortId}"

    def _action_required_based_on_participation_state(
        self, participation_state: SigningParticipationState, event: AttributeDict
    ) -> bool:
        """Check if an action is required for a given ritual event."""
        # does event have an associated action
        event_type = getattr(self.contract.events, event.event)
        event_has_associated_action = event_type in self.actions
        already_posted_signature = (
            event_type == self.contract.events.InitiateSigningCohort
            and participation_state.already_posted_signature
        )
        if any(
            [
                not event_has_associated_action,
                already_posted_signature,
            ]
        ):
            return False

        return True

    def _create_participation_state(
        self, event: AttributeDict
    ) -> SigningParticipationState:
        participation_state = self._get_latest_participation_state_values(event)
        return participation_state

    def _update_participation_state(
        self,
        cached_participation_state: SigningParticipationState,
        event: AttributeDict,
    ) -> None:
        # already tracked but cache values may be out of date
        self._get_latest_participation_state_values(event, cached_participation_state)

    def _get_cohort_participant_info(
        self, cohort_id: int
    ) -> Optional[SigningCoordinator.SigningCohortParticipant]:
        """
        Returns node's participant information for the provided
        ritual id; None if node is not participating in the ritual
        """
        is_participant = self.signing_coordinator_agent.is_signer(
            cohort_id=cohort_id, provider_address=self.operator.checksum_address
        )
        if is_participant:
            participant = self.signing_coordinator_agent.get_signer(
                cohort_id=cohort_id,
                provider=self.operator.checksum_address,
            )
            return participant

        return None

    def _get_latest_participation_state_values(
        self,
        event: AttributeDict,
        cached_participation_state: Optional[SigningParticipationState] = None,
    ) -> SigningParticipationState:
        """
        Obtains values for ParticipationState from the Coordinator contract.
        """
        event_type = getattr(self.contract.events, event.event)
        if cached_participation_state:
            if cached_participation_state.participating:
                if event_type == self.contract.events.SigningCohortDeployed:
                    cached_participation_state.already_posted_signature = True

                return cached_participation_state
            else:
                # not participating, nothing to do here
                return cached_participation_state

        new_participation_state = self.SigningParticipationState()
        args = event.args

        if event_type == self.contract.events.InitiateSigningCohort:
            # InitiateSigningCohort has all the information we need
            new_participation_state.participating = (
                self.operator.checksum_address in args.participants
            )
        else:
            # obtain information from contract
            participant_info = self._get_cohort_participant_info(
                cohort_id=args.cohortId
            )
            if participant_info:
                # actually participating in this ritual; get latest information
                new_participation_state.participating = True
                new_participation_state.already_posted_signature = bool(
                    participant_info.signer_address != NULL_ADDRESS
                )

        return new_participation_state

    def _handle_event(
        self,
        event: AttributeDict,
        get_block_when: Callable[[int], datetime.datetime],
    ):
        """
        Handle an event, invalidating cohort cache if needed before
        delegating to parent handler.
        """
        # Invalidate cohort cache for events that modify cohort data
        if event.event in self._CACHE_INVALIDATION_EVENTS:
            cohort_id = event.args.cohortId
            self.operator.clear_signing_cohort_cache(cohort_id)
            self.log.debug(
                f"Invalidated cohort cache for cohort {cohort_id} due to {event.event} event"
            )

        # Delegate to parent handler for normal event processing
        return super()._handle_event(event, get_block_when)
