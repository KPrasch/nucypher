"""
This file is part of nucypher.

nucypher is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

nucypher is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""

import random
from _pydecimal import Decimal
from collections import UserList
from enum import Enum

from eth_typing.evm import ChecksumAddress
from typing import Callable, Dict, Union

import maya
from constant_sorrow.constants import (
    EMPTY_STAKING_SLOT,
    NEW_STAKE,
    NOT_STAKING,
    UNTRACKED_PENDING_TRANSACTION
)
from eth_utils import currency
from hexbytes.main import HexBytes
from twisted.internet import reactor, task
from web3.exceptions import TransactionNotFound

from nucypher.blockchain.eth.agents import ContractAgency, StakingEscrowAgent
from nucypher.blockchain.eth.constants import AVERAGE_BLOCK_TIME_IN_SECONDS, NULL_ADDRESS
from nucypher.blockchain.eth.decorators import validate_checksum_address
from nucypher.blockchain.eth.registry import BaseContractRegistry
from nucypher.blockchain.eth.utils import datetime_at_period
from nucypher.types import SubStakeInfo, ERC20UNits, NuNits, TuNits, StakerInfo, Period
from nucypher.utilities.gas_strategies import EXPECTED_CONFIRMATION_TIME_IN_SECONDS
from nucypher.utilities.logging import Logger


class ERC20:
    """
    An amount of ERC20 tokens that doesn't hurt your eyes.
    Wraps the eth_utils currency conversion methods.

    The easiest way to use ERC20, is to pass an int, Decimal, or str, and denomination string:

    Int:    t = T(100, 'T')
    Int:    t = T(15000000000000000000000, 'TuNits')

    Decimal:  t = T(Decimal('15042.445'), 'T')
    String: t = T('10002.302', 'T')

    ...or alternately...

    Decimal: t = T.from_tokens(Decimal('100.50'))
    Int: t = T.from_units(15000000000000000000000)

    Token quantity is stored internally as an int in the smallest denomination,
    and all arithmetic operations use this value.

    Using float inputs to this class to represent amounts of NU is supported but not recommended,
    as floats don't have enough precision to represent some quantities.
    """

    _symbol = None
    _denominations = {}
    _unit_name = None

    class InvalidAmount(ValueError):
        """Raised when an invalid input amount is provided"""

    class InvalidDenomination(ValueError):
        """Raised when an unknown denomination string is passed into __init__"""

    def __init__(self, value: Union[int, Decimal, str], denomination: str):
        # super().__init__()
        # Lookup Conversion
        try:
            wrapped_denomination = self._denominations[denomination]
        except KeyError:
            raise self.InvalidDenomination(f'"{denomination}"')

        # Convert or Raise
        try:
            self.__value = currency.to_wei(number=value, unit=wrapped_denomination)
        except ValueError as e:
            raise self.__class__.InvalidAmount(f"{value} is an invalid amount of tokens: {str(e)}")

    @classmethod
    def ZERO(cls) -> 'ERC20':
        return cls(0, cls._unit_name)

    @classmethod
    def from_units(cls, value: int) -> 'ERC20':
        return cls(value, denomination=cls._unit_name)

    @classmethod
    def from_tokens(cls, value: Union[int, Decimal, str]) -> 'ERC20':
        return cls(value, denomination=cls._symbol)

    def to_tokens(self) -> Decimal:
        """Returns a decimal value of NU"""
        return currency.from_wei(self.__value, unit='ether')

    def to_units(self) -> ERC20UNits:
        """Returns an int value in the Unit class for this token"""
        return self.__class__._unit(self.__value)

    def __eq__(self, other) -> bool:
        return int(self) == int(other)

    def __bool__(self) -> bool:
        if self.__value == 0:
            return False
        else:
            return True

    def __radd__(self, other) -> 'ERC20':
        return self.__class__(int(self) + int(other), self._unit_name)

    def __add__(self, other) -> 'ERC20':
        return self.__class__(int(self) + int(other), self._unit_name)

    def __sub__(self, other) -> 'ERC20':
        return self.__class__(int(self) - int(other), self._unit_name)

    def __rmul__(self, other) -> 'ERC20':
        return self.__class__(int(self) * int(other), self._unit_name)

    def __mul__(self, other) -> 'ERC20':
        return self.__class__(int(self) * int(other), self._unit_name)

    def __floordiv__(self, other) -> 'ERC20':
        return self.__class__(int(self) // int(other), self._unit_name)

    def __gt__(self, other) -> bool:
        return int(self) > int(other)

    def __ge__(self, other) -> bool:
        return int(self) >= int(other)

    def __lt__(self, other) -> bool:
        return int(self) < int(other)

    def __le__(self, other) -> bool:
        return int(self) <= int(other)

    def __int__(self) -> int:
        """Cast to smallest denomination"""
        return int(self.to_units())

    def __round__(self, decimals: int = 0):
        return self.__class__.from_tokens(round(self.to_tokens(), decimals))

    def __repr__(self) -> str:
        r = f'{self._symbol}(value={str(self.__value)})'
        return r

    def __str__(self) -> str:
        return f'{str(self.to_tokens())} {self._symbol}'


class NU(ERC20):
    _symbol = 'NU'
    _denominations = {'NuNit': 'wei', 'NU': 'ether'}
    _unit_name = 'NuNit'
    _unit = NuNits


class TToken(ERC20):
    _symbol = 'T'
    _denominations = {'TuNit': 'wei', 'T': 'ether'}
    _unit_name = 'TuNit'
    _unit = TuNits


class Stake:
    """
    A quantity of tokens and staking duration in periods for one stake for one staker.
    """

    class StakingError(Exception):
        """Raised when a staking operation cannot be executed due to failure."""

    class Status(Enum):
        """
        Sub-stake status.
        """
        INACTIVE = 1   # Unlocked inactive
        UNLOCKED = 2   # Unlocked active
        LOCKED = 3     # Locked but not editable
        EDITABLE = 4   # Editable
        DIVISIBLE = 5  # Editable and divisible

        def is_child(self, other: 'Status') -> bool:
            if other == self.INACTIVE:
                return self == self.INACTIVE
            elif other == self.UNLOCKED:
                return self.value <= self.UNLOCKED.value
            else:
                return self.value >= other.value

    @validate_checksum_address
    def __init__(self,
                 staking_agent: StakingEscrowAgent,
                 checksum_address: str,
                 value: NU,
                 first_locked_period: int,
                 final_locked_period: int,
                 index: int,
                 economics):

        self.log = Logger(f'stake-{checksum_address}-{index}')

        # Ownership
        self.staker_address = checksum_address

        # Stake Metadata
        self.index = index
        self.value = value

        # Periods
        self.first_locked_period = first_locked_period

        # TODO: #1502 - Move Me Brightly - Docs
        # After this period has passes, workers can go offline, if this is the only stake.
        # This is the last period that can be committed for this stake.
        # Meaning, It must be committed in the previous period,
        # and no commitment can be made in this period for this stake.
        self.final_locked_period = final_locked_period

        # Blockchain
        self.staking_agent = staking_agent

        # Economics
        self.economics = economics
        self.minimum_nu = NU(int(self.economics.min_authorization), NU._unit_name)
        self.maximum_nu = NU(int(self.economics.maximum_allowed_locked), NU._unit_name)

        # Time
        self.start_datetime = datetime_at_period(period=first_locked_period,
                                                 seconds_per_period=self.economics.seconds_per_period,
                                                 start_of_period=True)
        self.unlock_datetime = datetime_at_period(period=final_locked_period + 1,
                                                  seconds_per_period=self.economics.seconds_per_period,
                                                  start_of_period=True)
        self._status = None

    def __repr__(self) -> str:
        r = f'Stake(' \
            f'index={self.index}, ' \
            f'value={self.value}, ' \
            f'end_period={self.final_locked_period}, ' \
            f'address={self.staker_address[:6]}, ' \
            f'escrow={self.staking_agent.contract_address[:6]}' \
            f')'
        return r

    def __eq__(self, other: 'Stake') -> bool:
        this_stake = (self.index,
                      self.value,
                      self.first_locked_period,
                      self.final_locked_period,
                      self.staker_address,
                      self.staking_agent.contract_address)
        try:
            that_stake = (other.index,
                          other.value,
                          other.first_locked_period,
                          other.final_locked_period,
                          other.staker_address,
                          other.staking_agent.contract_address)
        except AttributeError:
            return False

        return this_stake == that_stake

    @property
    def address_index_ordering_key(self):
        """To be used as a lexicographical order key for Stakes based on the tuple (staker_address, index)."""
        return self.staker_address, self.index

    #
    # Metadata
    #

    def status(self, staker_info: StakerInfo = None, current_period: Period = None) -> Status:
        """
        Returns status of sub-stake:
        UNLOCKED - final period in the past
        INACTIVE - UNLOCKED and sub-stake will not be included in any future calculations
        LOCKED - sub-stake is still locked and final period is current period
        EDITABLE - LOCKED and final period greater than current
        DIVISIBLE - EDITABLE and locked value is greater than two times the minimum allowed locked
        """

        if self._status:
            return self._status

        staker_info = staker_info or self.staking_agent.get_staker_info(self.staker_address) # TODO related to #1514
        current_period = current_period or self.staking_agent.get_current_period()  # TODO #1514 this is online only.

        if self.final_locked_period < current_period:
            if (staker_info.current_committed_period == 0 or
                staker_info.current_committed_period > self.final_locked_period) and \
                (staker_info.next_committed_period == 0 or
                 staker_info.next_committed_period > self.final_locked_period):
                self._status = Stake.Status.INACTIVE
            else:
                self._status = Stake.Status.UNLOCKED
        elif self.final_locked_period == current_period:
            self._status = Stake.Status.LOCKED
        elif self.value < 2 * self.economics.min_authorization:
            self._status = Stake.Status.EDITABLE
        else:
            self._status = Stake.Status.DIVISIBLE

        return self._status

    @classmethod
    @validate_checksum_address
    def from_stake_info(cls,
                        checksum_address: str,
                        index: int,
                        stake_info: SubStakeInfo,
                        economics,
                        *args, **kwargs
                        ) -> 'Stake':

        """Reads staking values as they exist on the blockchain"""

        instance = cls(checksum_address=checksum_address,
                       index=index,
                       first_locked_period=stake_info.first_period,
                       final_locked_period=stake_info.last_period,
                       value=NU(stake_info.locked_value, NU._unit_name),
                       economics=economics,
                       *args, **kwargs)

        return instance

    def to_stake_info(self) -> SubStakeInfo:
        """Returns a tuple representing the blockchain record of a stake"""
        return SubStakeInfo(self.first_locked_period, self.final_locked_period, self.value.to_units())

    #
    # Duration
    #

    @property
    def duration(self) -> int:
        """Return stake duration in periods"""
        result = (self.final_locked_period - self.first_locked_period) + 1
        return result

    @property
    def periods_remaining(self) -> int:
        """Returns the number of periods remaining in the stake from now."""
        current_period = self.staking_agent.get_current_period()
        return self.final_locked_period - current_period + 1

    def time_remaining(self, slang: bool = False) -> Union[int, str]:
        """
        Returns the time delta remaining in the stake from now.
        This method is designed for *UI* usage.
        """
        if slang:
            result = self.unlock_datetime.slang_date()
        else:
            # TODO - #1509 EthAgent?
            blocktime_epoch = self.staking_agent.blockchain.client.get_blocktime()
            delta = self.unlock_datetime.epoch - blocktime_epoch
            result = delta
        return result

    @property
    def kappa(self) -> float:
        """Returns the kappa factor for this substake based on its duration.
        The kappa factor grows linearly with duration, but saturates when it's longer than the maximum rewarded periods.
        See the economics papers for a more detailed description."""
        T_max = self.economics.maximum_rewarded_periods
        kappa = 0.5 * (1 + min(T_max, self.periods_remaining) / T_max)
        return kappa

    @property
    def boost(self) -> float:
        """An alternative representation of the kappa coefficient, easier to understand.
        Sub-stake boosts can range from 1x (i.e. no boost) to 2x (max boost). """

        min_kappa = 0.5
        boost = self.kappa / min_kappa
        return boost

    def describe(self) -> Dict[str, str]:
        start_datetime = self.start_datetime.local_datetime().strftime("%b %d %Y")
        end_datetime = self.unlock_datetime.local_datetime().strftime("%b %d %Y")

        data = dict(index=self.index,
                    value=str(self.value),
                    remaining=self.periods_remaining,
                    enactment=start_datetime,
                    last_period=end_datetime,
                    boost=f"{self.boost:.2f}x",
                    status=self.status().name)
        return data

    #
    # Blockchain
    #

    def sync(self) -> None:
        """Update this stakes attributes with on-chain values."""

        # Read from blockchain
        stake_info = self.staking_agent.get_substake_info(staker_address=self.staker_address,
                                                          stake_index=self.index)  # < -- Read from blockchain

        if not self.first_locked_period == stake_info.first_period:
            raise self.StakingError("Inconsistent staking cache.  Make sure your node is synced and try again.")

        # Mutate the instance with the on-chain values
        self.final_locked_period = stake_info.last_period
        self.value = NU.from_units(stake_info.locked_value)
        self._status = None

    @classmethod
    def initialize_stake(cls,
                         staking_agent,
                         economics,
                         checksum_address: str,
                         amount: NU,
                         lock_periods: int) -> 'Stake':

        # Value
        amount = NU(int(amount), NU._unit_name)

        # Duration
        current_period = staking_agent.get_current_period()
        final_locked_period = current_period + lock_periods

        stake = cls(checksum_address=checksum_address,
                    first_locked_period=current_period + 1,
                    final_locked_period=final_locked_period,
                    value=amount,
                    index=NEW_STAKE,
                    staking_agent=staking_agent,
                    economics=economics)

        # Validate
        validate_value(stake)
        validate_duration(stake)
        validate_max_value(stake)

        return stake


def validate_value(stake: Stake) -> None:
    """Validate a single staking value against pre-defined requirements"""
    if stake.minimum_nu > stake.value:
        raise Stake.StakingError(f'Stake amount of {stake.value} is too low; must be at least {stake.minimum_nu}')


def validate_duration(stake: Stake) -> None:
    """Validate a single staking lock-time against pre-defined requirements"""
    if stake.economics.min_operator_seconds > stake.duration:
        raise Stake.StakingError(
            'Stake duration of {duration} periods is too short; must be at least {minimum} periods.'
            .format(minimum=stake.economics.min_operator_seconds, duration=stake.duration))


def validate_divide(stake: Stake, target_value: NU, additional_periods: int = None) -> None:
    """
    Validates possibility to divide specified stake into two stakes using provided parameters.
    """

    # Ensure selected stake is active
    status = stake.status()
    if not status.is_child(Stake.Status.DIVISIBLE):
        raise Stake.StakingError(f'Cannot divide an non-divisible stake. '
                                 f'Selected stake expired {stake.unlock_datetime} and has value {stake.value}.')

    if target_value >= stake.value:
        raise Stake.StakingError(f"Cannot divide stake; Target value ({target_value}) must be less "
                                 f"than the existing stake value {stake.value}.")

    #
    # Generate SubStakes
    #

    # Modified Original Stake
    remaining_stake_value = stake.value - target_value
    modified_stake = Stake(checksum_address=stake.staker_address,
                           index=stake.index,
                           first_locked_period=stake.first_locked_period,
                           final_locked_period=stake.final_locked_period,
                           value=remaining_stake_value,
                           staking_agent=stake.staking_agent,
                           economics=stake.economics)

    # New Derived Stake
    end_period = stake.final_locked_period + additional_periods
    new_stake = Stake(checksum_address=stake.staker_address,
                      first_locked_period=stake.first_locked_period,
                      final_locked_period=end_period,
                      value=target_value,
                      index=NEW_STAKE,
                      staking_agent=stake.staking_agent,
                      economics=stake.economics)

    #
    # Validate
    #

    # Ensure both halves are for valid amounts
    validate_value(modified_stake)
    validate_value(new_stake)


def validate_max_value(stake: Stake, amount: NU = None) -> None:
    amount = amount or stake.value

    # Ensure the new stake will not exceed the staking limit
    locked_tokens = stake.staking_agent.get_locked_tokens(staker_address=stake.staker_address, periods=1)
    if (locked_tokens + amount) > stake.economics.maximum_allowed_locked:
        raise Stake.StakingError(f"Cannot initialize stake - "
                                 f"Maximum stake value exceeded for {stake.staker_address} "
                                 f"with a target value of {amount}.")


def validate_prolong(stake: Stake, additional_periods: int) -> None:
    status = stake.status()
    if not status.is_child(Stake.Status.EDITABLE):
        raise Stake.StakingError(f'Cannot prolong a non-editable stake. '
                                 f'Selected stake expired {stake.unlock_datetime}.')
    new_duration = stake.periods_remaining + additional_periods - 1
    if new_duration < stake.economics.min_operator_seconds:
        raise stake.StakingError(f'Sub-stake duration of {new_duration} periods after prolongation '
                                 f'is shorter than minimum allowed duration '
                                 f'of {stake.economics.min_operator_seconds} periods.')


def validate_merge(stake_1: Stake, stake_2: Stake) -> None:
    if stake_1.index == stake_2.index:
        raise Stake.StakingError(f'Stakes must be different. '
                                 f'Selected stakes have the same index {stake_1.index}.')

    if stake_1.final_locked_period != stake_2.final_locked_period:
        raise Stake.StakingError(f'Both stakes must have the same unlock date. '
                                 f'Selected stakes expired {stake_1.unlock_datetime} and {stake_2.unlock_datetime}.')

    status = stake_1.status()
    if not status.is_child(Stake.Status.EDITABLE):
        raise Stake.StakingError(f'Cannot merge a non-editable stakes. '
                                 f'Selected stakes expired {stake_1.unlock_datetime}.')


def validate_increase(stake: Stake, amount: NU) -> None:
    status = stake.status()
    if not status.is_child(Stake.Status.EDITABLE):
        raise Stake.StakingError(f'Cannot increase a non-editable stake. '
                                 f'Selected stake expired {stake.unlock_datetime}.')

    validate_max_value(stake=stake, amount=amount)


class WorkTrackerBase:
    """Baseclass for handling automated transaction tracking..."""

    CLOCK = reactor
    INTERVAL_FLOOR = 60 * 15  # fifteen minutes
    INTERVAL_CEIL = 60 * 180  # three hours

    ALLOWED_DEVIATION = 0.5  # i.e., up to +50% from the expected confirmation time

    def __init__(self, worker, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self.log = Logger('stake-tracker')
        self.worker = worker   # TODO: What to call the subject here?  What is a work tracker without "work"?

        self._tracking_task = task.LoopingCall(self._do_work)
        self._tracking_task.clock = self.CLOCK

        self.__pending = dict()  # TODO: Prime with pending worker transactions
        self.__requirement = None
        self.__start_time = NOT_STAKING
        self.__uptime_period = NOT_STAKING
        self._abort_on_error = False

        self._consecutive_fails = 0

        self._configure(*args)
        self.gas_strategy = worker.application_agent.blockchain.gas_strategy

    @classmethod
    def random_interval(cls, fails=None) -> int:
        if fails is not None and fails > 0:
            return cls.INTERVAL_FLOOR
        return random.randint(cls.INTERVAL_FLOOR, cls.INTERVAL_CEIL)

    def max_confirmation_time(self) -> int:
        expected_time = EXPECTED_CONFIRMATION_TIME_IN_SECONDS[self.gas_strategy]  # FIXME: #2447
        result = expected_time * (1 + self.ALLOWED_DEVIATION)
        return result

    def stop(self) -> None:
        if self._tracking_task.running:
            self._tracking_task.stop()
            self.log.info(f"STOPPED WORK TRACKING")

    def start(self, commit_now: bool = True, requirement_func: Callable = None, force: bool = False) -> None:
        """
        High-level stake tracking initialization, this function aims
        to be safely called at any time - For example, it is okay to call
        this function multiple times within the same period.
        """

        if self._tracking_task.running and not force:
            return

        # Add optional confirmation requirement callable
        self.__requirement = requirement_func

        # Record the start time and period
        self.__start_time = maya.now()

        self.log.info(f"START WORK TRACKING (immediate action: {commit_now})")
        d = self._tracking_task.start(interval=self.random_interval(fails=self._consecutive_fails), now=commit_now)
        d.addErrback(self.handle_working_errors)

    def _crash_gracefully(self, failure=None) -> None:
        """
        A facility for crashing more gracefully in the event that
        an exception is unhandled in a different thread.
        """
        self._crashed = failure
        failure.raiseException()

    def handle_working_errors(self, *args, **kwargs) -> None:
        failure = args[0]
        if self._abort_on_error:
            self.log.critical(f'Unhandled error during node work tracking. {failure!r}',
                              failure=failure)
            self.stop()
            reactor.callFromThread(self._crash_gracefully, failure=failure)
        else:
            self.log.warn(f'Unhandled error during work tracking (#{self._consecutive_fails}): {failure.getTraceback()!r}',
                          failure=failure)

            # the effect of this is that we get one immediate retry.
            # After that, the random_interval will be honored until
            # success is achieved
            commit_now = self._consecutive_fails < 1
            self._consecutive_fails += 1
            self.start(commit_now=commit_now)

    def __should_do_work_now(self) -> bool:
        # TODO: Check for stake expiration and exit
        if self.__requirement is None:
            return True
        r = self.__requirement(self.worker)
        if not isinstance(r, bool):
            raise ValueError(f"'requirement' must return a boolean.")
        return r

    @property
    def pending(self) -> Dict[int, HexBytes]:
        return self.__pending.copy()

    def __commitments_tracker_is_consistent(self) -> bool:
        operator_address = self.worker.operator_address
        tx_count_pending = self.client.get_transaction_count(account=operator_address, pending=True)
        tx_count_latest = self.client.get_transaction_count(account=operator_address, pending=False)
        txs_in_mempool = tx_count_pending - tx_count_latest

        if len(self.__pending) == txs_in_mempool:
            return True  # OK!

        if txs_in_mempool > len(self.__pending):  # We're missing some pending TXs
            return False
        else:  # TODO #2429: What to do when txs_in_mempool < len(self.__pending)? What does this imply?
            return True

    def __track_pending_commitments(self) -> bool:
        # TODO: Keep a purpose-built persistent log of worker transaction history

        unmined_transactions = 0
        pending_transactions = self.pending.items()    # note: this must be performed non-mutatively
        for tx_firing_block_number, txhash in sorted(pending_transactions):
            if txhash is UNTRACKED_PENDING_TRANSACTION:
                unmined_transactions += 1
                continue

            try:
                confirmed_tx_receipt = self.client.get_transaction_receipt(transaction_hash=txhash)
            except TransactionNotFound:
                unmined_transactions += 1  # mark as unmined - Keep tracking it for now
                continue
            else:
                confirmation_block_number = confirmed_tx_receipt['blockNumber']
                confirmations = confirmation_block_number - tx_firing_block_number
                self.log.info(f'Commitment transaction {txhash.hex()[:10]} confirmed: {confirmations} confirmations')
                del self.__pending[tx_firing_block_number]

        if unmined_transactions:
            s = "s" if unmined_transactions > 1 else ""
            self.log.info(f'{unmined_transactions} pending commitment transaction{s} detected.')

        inconsistent_tracker = not self.__commitments_tracker_is_consistent()
        if inconsistent_tracker:
            # If we detect there's a mismatch between the number of internally tracked and
            # pending block transactions, create a special pending TX that accounts for this.
            # TODO: Detect if this untracked pending transaction is a commitment transaction at all.
            self.__pending[0] = UNTRACKED_PENDING_TRANSACTION
            return True

        return bool(self.__pending)

    def _fire_replacement_commitment(self, current_block_number: int, tx_firing_block_number: int) -> None:
        replacement_txhash = self._fire_commitment()  # replace
        self.__pending[current_block_number] = replacement_txhash  # track this transaction
        del self.__pending[tx_firing_block_number]  # assume our original TX is stuck

    def _handle_replacement_commitment(self, current_block_number: int) -> None:
        tx_firing_block_number, txhash = list(sorted(self.pending.items()))[0]
        if txhash is UNTRACKED_PENDING_TRANSACTION:
            # TODO: Detect if this untracked pending transaction is a commitment transaction at all.
            message = f"We have an untracked pending transaction. Issuing a replacement transaction."
        else:
            # If the transaction is still not mined after a max confirmation time
            # (based on current gas strategy) issue a replacement transaction.
            wait_time_in_blocks = current_block_number - tx_firing_block_number
            wait_time_in_seconds = wait_time_in_blocks * AVERAGE_BLOCK_TIME_IN_SECONDS
            if wait_time_in_seconds < self.max_confirmation_time():
                self.log.info(f'Waiting for pending commitment transaction to be mined ({txhash.hex()}).')
                return
            else:
                message = f"We've waited for {wait_time_in_seconds}, but max time is {self.max_confirmation_time()}" \
                          f" for {self.gas_strategy} gas strategy. Issuing a replacement transaction."

        # Send a replacement transaction
        self.log.info(message)
        self.__fire_replacement_commitment(current_block_number=current_block_number,
                                           tx_firing_block_number=tx_firing_block_number)

    def __reset_tracker_state(self) -> None:
        self.__pending.clear()  # Forget the past. This is a new beginning.
        self._consecutive_fails = 0

    def _do_work(self) -> None:
        """
        Async working task for Ursula  # TODO: Split into multiple async tasks
        """

        self.log.info(f"{self.__class__.__name__} is running. Advancing to next work cycle.")  # TODO: What to call the verb the subject performs?

        # Call once here, and inject later for temporal consistency
        current_block_number = self.client.block_number

        if self._prep_work_state() is False:
            return

        # Commitment tracking
        unmined_transactions = self.__track_pending_commitments()
        if unmined_transactions:
            self.log.info('Tracking pending transaction.')
            self.__handle_replacement_commitment(current_block_number=current_block_number)
            # while there are known pending transactions, remain in fast interval mode
            self._tracking_task.interval = self.INTERVAL_FLOOR
            return  # This cycle is finished.
        else:
            # Randomize the next task interval over time, within bounds.
            self._tracking_task.interval = self.random_interval(fails=self._consecutive_fails)

        # Only perform work this round if the requirements are met
        if not self.__should_do_work_now():
            self.log.warn(f'COMMIT PREVENTED (callable: "{self.__requirement.__name__}") - '
                          f'Situation does not call for doing work now.')
            # TODO: Follow-up actions for failed requirements
            return

        if self._final_work_prep_before_transaction() is False:
            return

        txhash = self._fire_commitment()
        self.__pending[current_block_number] = txhash

    #  the following four methods are specific to PRE network schemes and must be implemented as below
    def _configure(self, stakes):
        """ post __init__ configuration dealing with contracts or state specific to this PRE flavor"""
        raise NotImplementedError

    def _prep_work_state(self):
        """ configuration perfomed before transaction management in task execution """
        raise NotImplementedError

    def _final_work_prep_before_transaction(self):
        """ configuration perfomed after transaction management in task execution right before transaction firing"""
        raise NotImplementedError()

    def _fire_commitment(self):
        """ actually fire the tranasction """
        raise NotImplementedError


class WorkTracker(WorkTrackerBase):

    INTERVAL_FLOOR = 1
    INTERVAL_CEIL = 2

    def _configure(self, *args):
        self.application_agent = self.worker.application_agent
        self.client = self.application_agent.blockchain.client

    def _prep_work_state(self):
        return True

    def _final_work_prep_before_transaction(self):
        should_continue = self.worker.get_staking_provider_address() != NULL_ADDRESS
        if should_continue:
            return True
        self.log.warn('COMMIT PREVENTED - Operator is not bonded to an operator.')
        return False

    def _fire_commitment(self):
        """Makes an initial/replacement operator commitment transaction"""
        transacting_power = self.worker.transacting_power
        with transacting_power:
            txhash = self.worker.confirm_address(fire_and_forget=True)  # < --- blockchain WRITE
            self.log.info(f"Confirming operator address {self.worker.operator_address} with staking provider {self.worker.staking_provider_address} - TxHash: {txhash.hex()}")
            return txhash


class StakeList(UserList):

    @validate_checksum_address
    def __init__(self,
                 registry: BaseContractRegistry,
                 checksum_address: ChecksumAddress = None,  # allow for lazy setting
                 *args, **kwargs):

        super().__init__(*args, **kwargs)
        self.log = Logger('stake-tracker')
        self.staking_agent = ContractAgency.get_agent(StakingEscrowAgent, registry=registry)
        from nucypher.blockchain.economics import EconomicsFactory
        self.economics = EconomicsFactory.get_economics(registry=registry)

        self.__initial_period = NOT_STAKING
        self.__terminal_period = NOT_STAKING

        # "load-in" Read on-chain stakes
        self.checksum_address = checksum_address
        self.__updated = None

    @property
    def updated(self) -> maya.MayaDT:
        return self.__updated

    @property
    def initial_period(self) -> int:
        return self.__initial_period

    @property
    def terminal_period(self) -> int:
        return self.__terminal_period

    @validate_checksum_address
    def refresh(self) -> None:
        """Public staking cache invalidation method"""
        return self.__read_stakes()

    def __read_stakes(self) -> None:
        """Rewrite the local staking cache by reading on-chain stakes"""

        existing_records = len(self)

        # Candidate replacement cache values
        current_period = self.staking_agent.get_current_period()
        onchain_stakes, initial_period, terminal_period = list(), 0, current_period

        # Read from blockchain
        stakes_reader = self.staking_agent.get_all_stakes(staker_address=self.checksum_address)
        inactive_substakes = []
        for onchain_index, stake_info in enumerate(stakes_reader):

            if not stake_info:
                onchain_stake = EMPTY_STAKING_SLOT

            else:
                onchain_stake = Stake.from_stake_info(checksum_address=self.checksum_address,
                                                      stake_info=stake_info,
                                                      staking_agent=self.staking_agent,
                                                      index=onchain_index,
                                                      economics=self.economics)

                # rack the earliest terminal period
                if onchain_stake.first_locked_period:
                    if onchain_stake.first_locked_period < initial_period:
                        initial_period = onchain_stake.first_locked_period

                # rack the latest terminal period
                if onchain_stake.final_locked_period > terminal_period:
                    terminal_period = onchain_stake.final_locked_period

                if onchain_stake.status().is_child(Stake.Status.INACTIVE):
                    inactive_substakes.append(onchain_index)

            # Store the replacement stake
            onchain_stakes.append(onchain_stake)

        # Commit the new stake and terminal values to the cache
        self.data = onchain_stakes
        if onchain_stakes:
            self.__initial_period = initial_period
            self.__terminal_period = terminal_period
            changed_records = abs(existing_records - len(onchain_stakes))
            self.log.debug(f"Updated {changed_records} local staking cache entries.")
            if inactive_substakes:
                self.log.debug(f"The following sub-stakes are inactive: {inactive_substakes}")

        # Record most recent cache update
        self.__updated = maya.now()

    @property
    def has_active_substakes(self) -> bool:
        current_period = self.staking_agent.get_current_period()
        for stake in self.data:
            if not stake.status(current_period=current_period).is_child(Stake.Status.INACTIVE):
                return True
