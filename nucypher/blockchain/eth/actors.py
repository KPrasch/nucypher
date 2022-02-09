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


import json
import time
from decimal import Decimal
from typing import Callable, Union
from typing import Iterable, List, Optional, Tuple

import maya
from constant_sorrow.constants import FULL
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3 import Web3
from web3.types import TxReceipt

from nucypher.acumen.nicknames import Nickname
from nucypher.blockchain.economics import (
    Economics,
    EconomicsFactory,
)
from nucypher.blockchain.eth.agents import (
    AdjudicatorAgent,
    ContractAgency,
    NucypherTokenAgent,
    PolicyManagerAgent,
    StakingEscrowAgent,
    PREApplicationAgent
)
from nucypher.blockchain.eth.constants import (
    NULL_ADDRESS,
)
from nucypher.blockchain.eth.decorators import (
    only_me,
    save_receipt,
    validate_checksum_address
)
from nucypher.blockchain.eth.deployers import (
    AdjudicatorDeployer,
    BaseContractDeployer,
    NucypherTokenDeployer,
    PolicyManagerDeployer,
    StakingEscrowDeployer,
    StakingInterfaceDeployer,
    PREApplicationDeployer,
    SubscriptionManagerDeployer
)
from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
from nucypher.blockchain.eth.registry import BaseContractRegistry
from nucypher.blockchain.eth.signers.base import Signer
from nucypher.blockchain.eth.token import (
    NU,
    Stake,
    StakeList,
    WorkTracker,
    validate_prolong,
    validate_increase,
    validate_divide,
    validate_merge
)
from nucypher.blockchain.eth.utils import (
    calculate_period_duration,
    datetime_to_period
)
from nucypher.characters.banners import STAKEHOLDER_BANNER
from nucypher.config.constants import DEFAULT_CONFIG_ROOT
from nucypher.control.emitters import StdoutEmitter
from nucypher.crypto.powers import TransactingPower
from nucypher.types import NuNits, Period
from nucypher.utilities.logging import Logger


class BaseActor:
    """
    Concrete base class for any actor that will interface with NuCypher's ethereum smart contracts.
    """

    class ActorError(Exception):
        pass

    @validate_checksum_address
    def __init__(self,
                 domain: Optional[str],
                 registry: BaseContractRegistry,
                 transacting_power: Optional[TransactingPower] = None,
                 checksum_address: Optional[ChecksumAddress] = None,
                 economics: Optional[Economics] = None):

        if not (bool(checksum_address) ^ bool(transacting_power)):
            error = f'Pass transacting power or checksum address, got {checksum_address} and {transacting_power}.'
            raise ValueError(error)

        try:
            parent_address = self.checksum_address
            if checksum_address is not None:
                if parent_address != checksum_address:
                    raise ValueError(f"Can't have two different ethereum addresses. "
                                     f"Got {parent_address} and {checksum_address}.")
        except AttributeError:
            if transacting_power:
                self.checksum_address = transacting_power.account
            else:
                self.checksum_address = checksum_address

        self.economics = economics or Economics()
        self.transacting_power = transacting_power
        self.registry = registry
        self.network = domain
        self._saved_receipts = list()  # track receipts of transmitted transactions

    def __repr__(self):
        class_name = self.__class__.__name__
        r = "{}(address='{}')"
        r = r.format(class_name, self.checksum_address)
        return r

    def __eq__(self, other) -> bool:
        """Actors are equal if they have the same address."""
        try:
            return bool(self.checksum_address == other.checksum_address)
        except AttributeError:
            return False

    @property
    def eth_balance(self) -> Decimal:
        """Return this actor's current ETH balance"""
        blockchain = BlockchainInterfaceFactory.get_interface()  # TODO: EthAgent?  #1509
        balance = blockchain.client.get_balance(self.wallet_address)
        return Web3.fromWei(balance, 'ether')

    @property
    def wallet_address(self):
        return self.checksum_address


class NucypherTokenActor(BaseActor):
    """
    Actor to interface with the NuCypherToken contract
    """

    def __init__(self, registry: BaseContractRegistry, **kwargs):
        super().__init__(registry=registry, **kwargs)
        self.__token_agent = None

    @property
    def token_agent(self):
        if self.__token_agent:
            return self.__token_agent
        self.__token_agent = ContractAgency.get_agent(NucypherTokenAgent, registry=self.registry)
        return self.__token_agent

    @property
    def token_balance(self) -> NU:
        """Return this actor's current token balance"""
        balance = int(self.token_agent.get_balance(address=self.checksum_address))
        nu_balance = NU(balance, 'NuNit')
        return nu_balance


class ContractAdministrator(BaseActor):
    """
    The administrator of network contracts.
    """

    # Note: Deployer classes are sorted by deployment dependency order.

    standard_deployer_classes = (
        NucypherTokenDeployer,
        PREApplicationDeployer,
        SubscriptionManagerDeployer  # TODO: Move to dispatched/upgradeable section
    )

    dispatched_upgradeable_deployer_classes = (
        StakingEscrowDeployer,
        PolicyManagerDeployer,
        AdjudicatorDeployer,
    )

    upgradeable_deployer_classes = (
        *dispatched_upgradeable_deployer_classes,
        StakingInterfaceDeployer,
    )

    aux_deployer_classes = (
        # Add more deployer classes here
    )

    # For ownership transfers.
    ownable_deployer_classes = (*dispatched_upgradeable_deployer_classes,
                                StakingInterfaceDeployer)

    # Used in the automated deployment series.
    primary_deployer_classes = (*standard_deployer_classes,
                                *upgradeable_deployer_classes)

    # Comprehensive collection.
    all_deployer_classes = (*primary_deployer_classes,
                            *aux_deployer_classes,
                            *ownable_deployer_classes)

    class UnknownContract(ValueError):
        pass

    def __init__(self, *args, **kwargs):
        self.log = Logger("Deployment-Actor")
        self.deployers = {d.contract_name: d for d in self.all_deployer_classes}
        super().__init__(*args, **kwargs)

    def __repr__(self):
        r = '{name} - {deployer_address})'.format(name=self.__class__.__name__, deployer_address=self.checksum_address)
        return r

    def __get_deployer(self, contract_name: str):
        try:
            Deployer = self.deployers[contract_name]
        except KeyError:
            raise self.UnknownContract(contract_name)
        return Deployer

    def deploy_contract(self,
                        contract_name: str,
                        gas_limit: int = None,
                        deployment_mode=FULL,
                        ignore_deployed: bool = False,
                        progress=None,
                        confirmations: int = 0,
                        deployment_parameters: dict = None,
                        emitter=None,
                        *args, **kwargs,
                        ) -> Tuple[dict, BaseContractDeployer]:

        if not self.transacting_power:
            raise self.ActorError('No transacting power available for deployment.')

        deployment_parameters = deployment_parameters or {}

        Deployer = self.__get_deployer(contract_name=contract_name)
        deployer = Deployer(registry=self.registry, economics=self.economics, *args, **kwargs)

        if Deployer._upgradeable:
            receipts = deployer.deploy(transacting_power=self.transacting_power,
                                       gas_limit=gas_limit,
                                       progress=progress,
                                       ignore_deployed=ignore_deployed,
                                       confirmations=confirmations,
                                       deployment_mode=deployment_mode,
                                       emitter=emitter,
                                       **deployment_parameters)
        else:
            receipts = deployer.deploy(transacting_power=self.transacting_power,
                                       gas_limit=gas_limit,
                                       progress=progress,
                                       confirmations=confirmations,
                                       deployment_mode=deployment_mode,
                                       ignore_deployed=ignore_deployed,
                                       emitter=emitter,
                                       **deployment_parameters)
        return receipts, deployer

    def upgrade_contract(self,
                         contract_name: str,
                         confirmations: int,
                         ignore_deployed: bool = False,
                         ) -> dict:
        if not self.transacting_power:
            raise self.ActorError('No transacting power available for deployment.')
        Deployer = self.__get_deployer(contract_name=contract_name)
        deployer = Deployer(registry=self.registry)
        receipts = deployer.upgrade(transacting_power=self.transacting_power,
                                    ignore_deployed=ignore_deployed,
                                    confirmations=confirmations)
        return receipts

    def retarget_proxy(self,
                       confirmations: int,
                       contract_name: str,
                       target_address: str,
                       just_build_transaction: bool = False
                       ):
        if not self.transacting_power:
            raise self.ActorError('No transacting power available for deployment.')
        Deployer = self.__get_deployer(contract_name=contract_name)
        deployer = Deployer(registry=self.registry)
        result = deployer.retarget(transacting_power=self.transacting_power,
                                   target_address=target_address,
                                   just_build_transaction=just_build_transaction,
                                   confirmations=confirmations)
        return result

    def rollback_contract(self, contract_name: str):
        if not self.transacting_power:
            raise self.ActorError('No transacting power available for deployment.')
        Deployer = self.__get_deployer(contract_name=contract_name)
        deployer = Deployer(registry=self.registry)
        receipts = deployer.rollback(transacting_power=self.transacting_power)
        return receipts

    def save_deployment_receipts(self, receipts: dict, filename_prefix: str = 'deployment') -> str:
        config_root = DEFAULT_CONFIG_ROOT  # We force the use of the default here.
        filename = f'{filename_prefix}-receipts-{self.deployer_address[:6]}-{maya.now().epoch}.json'
        filepath = config_root / filename
        config_root.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as file:
            data = dict()
            for contract_name, contract_receipts in receipts.items():
                contract_records = dict()
                for tx_name, receipt in contract_receipts.items():
                    # Formatting
                    pretty_receipt = {item: str(result) for item, result in receipt.items()}
                    contract_records[tx_name] = pretty_receipt
                data[contract_name] = contract_records
            data = json.dumps(data, indent=4)
            file.write(data)
        return filepath

    def set_fee_rate_range(self,
                           minimum: int,
                           default: int,
                           maximum: int,
                           transaction_gas_limit: int = None) -> TxReceipt:
        if not self.transacting_power:
            raise self.ActorError('No transacting power available.')
        policy_manager_deployer = PolicyManagerDeployer(registry=self.registry, economics=self.economics)
        receipt = policy_manager_deployer.set_fee_rate_range(transacting_power=self.transacting_power,
                                                             minimum=minimum,
                                                             default=default,
                                                             maximum=maximum,
                                                             gas_limit=transaction_gas_limit)
        return receipt


class Staker(NucypherTokenActor):
    """
    Baseclass for staking-related operations on the blockchain.
    """

    class StakerError(NucypherTokenActor.ActorError):
        pass

    class InsufficientTokens(StakerError):
        pass

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.log = Logger("staker")
        self.is_me = bool(self.transacting_power)
        self._operator_address = None

        # Blockchain
        self.policy_agent = ContractAgency.get_agent(PolicyManagerAgent, registry=self.registry)
        self.staking_agent = ContractAgency.get_agent(StakingEscrowAgent, registry=self.registry)
        self.economics = EconomicsFactory.get_economics(registry=self.registry)

        # Check stakes
        self.stakes = StakeList(registry=self.registry, checksum_address=self.checksum_address)

    def refresh_stakes(self):
        self.stakes.refresh()

    def to_dict(self) -> dict:
        stake_info = [stake.to_stake_info() for stake in self.stakes]
        operator_address = self.operator_address or NULL_ADDRESS
        staker_funds = {'ETH': int(self.eth_balance), 'NU': int(self.token_balance)}
        staker_payload = {'staker': self.checksum_address,
                          'balances': staker_funds,
                          'operator': operator_address,
                          'stakes': stake_info}
        return staker_payload

    @property
    def is_staking(self) -> bool:
        """Checks if this Staker currently has active stakes / locked tokens."""
        return bool(self.stakes)

    def owned_tokens(self) -> NU:
        """
        Returns all tokens that belong to the staker, including locked, unlocked and rewards.
        """
        raw_value = self.staking_agent.owned_tokens(staker_address=self.checksum_address)
        value = NU.from_units(raw_value)
        return value

    def locked_tokens(self, periods: int = 0) -> NU:
        """Returns the amount of tokens this staker has locked for a given duration in periods."""
        raw_value = self.staking_agent.get_locked_tokens(staker_address=self.checksum_address, periods=periods)
        value = NU.from_units(raw_value)
        return value

    @property
    def current_stake(self) -> NU:
        """The total number of staked tokens, i.e., tokens locked in the current period."""
        return self.locked_tokens(periods=0)

    def filtered_stakes(self,
                        parent_status: Stake.Status = None,
                        filter_function: Callable[[Stake], bool] = None
                        ) -> Iterable[Stake]:
        """Returns stakes for this staker which filtered by status or by a provided function."""
        if not parent_status and not filter_function:
            raise ValueError("Pass parent status or filter function or both.")

        # Read once from chain and reuse these values
        staker_info = self.staking_agent.get_staker_info(self.checksum_address)  # TODO related to #1514
        current_period = self.staking_agent.get_current_period()                 # TODO #1514 this is online only.

        stakes = list()
        for stake in self.stakes:
            if parent_status and not stake.status(staker_info, current_period).is_child(parent_status):
                continue
            if filter_function and not filter_function(stake):
                continue
            stakes.append(stake)

        return stakes

    def sorted_stakes(self,
                      parent_status: Stake.Status = None,
                      filter_function: Callable[[Stake], bool] = None
                      ) -> List[Stake]:
        """Returns a list of filtered stakes sorted by account wallet index."""
        if parent_status is not None or filter_function is not None:
            filtered_stakes = self.filtered_stakes(parent_status, filter_function)
        else:
            filtered_stakes = self.stakes

        stakes = sorted(filtered_stakes, key=lambda s: s.address_index_ordering_key)
        return stakes

    @only_me
    def initialize_stake(self,
                         amount: NU = None,
                         lock_periods: int = None,
                         expiration: maya.MayaDT = None,
                         entire_balance: bool = False,
                         from_unlocked: bool = False
                         ) -> TxReceipt:

        """Create a new stake."""

        # Duration
        if not (bool(lock_periods) ^ bool(expiration)):
            raise ValueError(f"Pass either lock periods or expiration; got {'both' if lock_periods else 'neither'}")
        if expiration:
            lock_periods = calculate_period_duration(future_time=expiration,
                                                     seconds_per_period=self.economics.seconds_per_period)

        # Value
        if entire_balance and amount:
            raise ValueError("Specify an amount or entire balance, not both")
        elif not entire_balance and not amount:
            raise ValueError("Specify an amount or entire balance, got neither")

        token_balance = self.calculate_staking_reward() if from_unlocked else self.token_balance
        if entire_balance:
            amount = token_balance
        if not token_balance >= amount:
            raise self.InsufficientTokens(f"Insufficient token balance ({token_balance}) "
                                          f"for new stake initialization of {amount}")

        # Write to blockchain
        new_stake = Stake.initialize_stake(staking_agent=self.staking_agent,
                                           economics=self.economics,
                                           checksum_address=self.checksum_address,
                                           amount=amount,
                                           lock_periods=lock_periods)

        # Create stake on-chain
        if from_unlocked:
            receipt = self._lock_and_create(amount=new_stake.value.to_units(), lock_periods=new_stake.duration)
        else:
            receipt = self._deposit(amount=new_stake.value.to_units(), lock_periods=new_stake.duration)

        # Log and return receipt
        self.log.info(f"{self.checksum_address} initialized new stake: {amount} tokens for {lock_periods} periods")

        # Update staking cache element
        self.refresh_stakes()

        return receipt

    def _ensure_stake_exists(self, stake: Stake):
        if len(self.stakes) <= stake.index:
            raise ValueError(f"There is no stake with index {stake.index}")
        if self.stakes[stake.index] != stake:
            raise ValueError(f"Stake with index {stake.index} is not equal to provided stake")

    @only_me
    def divide_stake(self,
                     stake: Stake,
                     target_value: NU,
                     additional_periods: int = None,
                     expiration: maya.MayaDT = None
                     ) -> TxReceipt:
        self._ensure_stake_exists(stake)

        if not (bool(additional_periods) ^ bool(expiration)):
            raise ValueError(f"Pass either the number of lock periods or expiration; "
                             f"got {'both' if additional_periods else 'neither'}")

        # Calculate stake duration in periods
        if expiration:
            additional_periods = datetime_to_period(datetime=expiration, seconds_per_period=self.economics.seconds_per_period) - stake.final_locked_period
            if additional_periods <= 0:
                raise ValueError(f"New expiration {expiration} must be at least 1 period from the "
                                 f"current stake's end period ({stake.final_locked_period}).")

        # Read on-chain stake and validate
        stake.sync()
        validate_divide(stake=stake, target_value=target_value, additional_periods=additional_periods)

        # Do it already!
        receipt = self._divide_stake(stake_index=stake.index,
                                     additional_periods=additional_periods,
                                     target_value=int(target_value))

        # Update staking cache element
        self.refresh_stakes()

        return receipt

    @only_me
    def increase_stake(self,
                       stake: Stake,
                       amount: NU = None,
                       entire_balance: bool = False,
                       from_unlocked: bool = False
                       ) -> TxReceipt:
        """Add tokens to existing stake."""
        self._ensure_stake_exists(stake)

        # Value
        if not (bool(entire_balance) ^ bool(amount)):
            raise ValueError(f"Pass either an amount or entire balance; "
                             f"got {'both' if entire_balance else 'neither'}")

        token_balance = self.calculate_staking_reward() if from_unlocked else self.token_balance
        if entire_balance:
            amount = token_balance
        if not token_balance >= amount:
            raise self.InsufficientTokens(f"Insufficient token balance ({token_balance}) "
                                          f"to increase stake by {amount}")

        # Read on-chain stake and validate
        stake.sync()
        validate_increase(stake=stake, amount=amount)

        # Write to blockchain
        if from_unlocked:
            receipt = self._lock_and_increase(stake_index=stake.index, amount=int(amount))
        else:
            receipt = self._deposit_and_increase(stake_index=stake.index, amount=int(amount))

        # Update staking cache element
        self.refresh_stakes()
        return receipt

    @only_me
    def prolong_stake(self,
                      stake: Stake,
                      additional_periods: int = None,
                      expiration: maya.MayaDT = None
                      ) -> TxReceipt:
        self._ensure_stake_exists(stake)

        if not (bool(additional_periods) ^ bool(expiration)):
            raise ValueError(f"Pass either the number of lock periods or expiration; "
                             f"got {'both' if additional_periods else 'neither'}")

        # Calculate stake duration in periods
        if expiration:
            additional_periods = datetime_to_period(datetime=expiration,
                                                    seconds_per_period=self.economics.seconds_per_period) - stake.final_locked_period
            if additional_periods <= 0:
                raise ValueError(f"New expiration {expiration} must be at least 1 period from the "
                                 f"current stake's end period ({stake.final_locked_period}).")

        # Read on-chain stake and validate
        stake.sync()
        validate_prolong(stake=stake, additional_periods=additional_periods)

        receipt = self._prolong_stake(stake_index=stake.index, lock_periods=additional_periods)

        # Update staking cache element
        self.refresh_stakes()
        return receipt

    @only_me
    def merge_stakes(self,
                     stake_1: Stake,
                     stake_2: Stake
                     ) -> TxReceipt:
        self._ensure_stake_exists(stake_1)
        self._ensure_stake_exists(stake_2)

        # Read on-chain stake and validate
        stake_1.sync()
        stake_2.sync()
        validate_merge(stake_1=stake_1, stake_2=stake_2)

        receipt = self._merge_stakes(stake_index_1=stake_1.index, stake_index_2=stake_2.index)

        # Update staking cache element
        self.refresh_stakes()
        return receipt

    def _prolong_stake(self, stake_index: int, lock_periods: int) -> TxReceipt:
        """Public facing method for stake prolongation."""
        receipt = self.staking_agent.prolong_stake(stake_index=stake_index,
                                                   periods=lock_periods,
                                                   transacting_power=self.transacting_power)
        return receipt

    def _deposit(self, amount: int, lock_periods: int) -> TxReceipt:
        """Public facing method for token locking."""
        self._ensure_allowance_equals(0)
        receipt = self.token_agent.approve_and_call(amount=amount,
                                                    target_address=self.staking_agent.contract_address,
                                                    transacting_power=self.transacting_power,
                                                    call_data=Web3.toBytes(lock_periods))
        return receipt

    def _lock_and_create(self, amount: int, lock_periods: int) -> TxReceipt:
        """Public facing method for token locking without depositing."""
        receipt = self.staking_agent.lock_and_create(amount=amount,
                                                     transacting_power=self.transacting_power,
                                                     lock_periods=lock_periods)
        return receipt

    def _divide_stake(self, stake_index: int, additional_periods: int, target_value: int) -> TxReceipt:
        """Public facing method for stake dividing."""
        receipt = self.staking_agent.divide_stake(transacting_power=self.transacting_power,
                                                  stake_index=stake_index,
                                                  target_value=target_value,
                                                  periods=additional_periods)
        return receipt

    def _deposit_and_increase(self, stake_index: int, amount: int) -> TxReceipt:
        """Public facing method for deposit and increasing stake."""
        self._ensure_allowance_equals(amount)
        receipt = self.staking_agent.deposit_and_increase(transacting_power=self.transacting_power,
                                                          stake_index=stake_index,
                                                          amount=amount)
        return receipt

    def _ensure_allowance_equals(self, amount: int):
        owner = self.transacting_power.account
        spender = self.staking_agent.contract.address
        current_allowance = self.token_agent.get_allowance(owner=owner, spender=spender)
        if amount > current_allowance:
            to_increase = amount - current_allowance
            self.token_agent.increase_allowance(increase=to_increase,
                                                transacting_power=self.transacting_power,
                                                spender_address=spender)
            self.log.info(f"{owner} increased token allowance for spender {spender} to {amount}")
        elif amount < current_allowance:
            to_decrease = current_allowance - amount
            self.token_agent.decrease_allowance(decrease=to_decrease,
                                                transacting_power=self.transacting_power,
                                                spender_address=spender)
            self.log.info(f"{owner} decreased token allowance for spender {spender} to {amount}")

    def _lock_and_increase(self, stake_index: int, amount: int) -> TxReceipt:
        """Public facing method for increasing stake."""
        receipt = self.staking_agent.lock_and_increase(transacting_power=self.transacting_power,
                                                       stake_index=stake_index,
                                                       amount=amount)
        return receipt

    def _merge_stakes(self, stake_index_1: int, stake_index_2: int) -> TxReceipt:
        """Public facing method for stakes merging."""
        receipt = self.staking_agent.merge_stakes(stake_index_1=stake_index_1,
                                                  stake_index_2=stake_index_2,
                                                  transacting_power=self.transacting_power)
        return receipt

    @property
    def is_restaking(self) -> bool:
        restaking = self.staking_agent.is_restaking(staker_address=self.checksum_address)
        return restaking

    @only_me
    @save_receipt
    def _set_restaking(self, value: bool) -> TxReceipt:
        receipt = self.staking_agent.set_restaking(transacting_power=self.transacting_power, value=value)
        return receipt

    def enable_restaking(self) -> TxReceipt:
        receipt = self._set_restaking(value=True)
        return receipt

    def disable_restaking(self) -> TxReceipt:
        receipt = self._set_restaking(value=False)
        return receipt

    @property
    def is_winding_down(self) -> bool:
        winding_down = self.staking_agent.is_winding_down(staker_address=self.checksum_address)
        return winding_down

    @only_me
    @save_receipt
    def _set_winding_down(self, value: bool) -> TxReceipt:
        receipt = self.staking_agent.set_winding_down(transacting_power=self.transacting_power, value=value)
        return receipt

    def enable_winding_down(self) -> TxReceipt:
        receipt = self._set_winding_down(value=True)
        return receipt

    def disable_winding_down(self) -> TxReceipt:
        receipt = self._set_winding_down(value=False)
        return receipt

    @property
    def is_taking_snapshots(self) -> bool:
        taking_snapshots = self.staking_agent.is_taking_snapshots(staker_address=self.checksum_address)
        return taking_snapshots

    @only_me
    @save_receipt
    def _set_snapshots(self, value: bool) -> TxReceipt:
        receipt = self.staking_agent.set_snapshots(transacting_power=self.transacting_power, activate=value)
        return receipt

    def enable_snapshots(self) -> TxReceipt:
        receipt = self._set_snapshots(value=True)
        return receipt

    def disable_snapshots(self) -> TxReceipt:
        receipt = self._set_snapshots(value=False)
        return receipt

    @property
    def is_migrated(self) -> bool:
        migrated = self.staking_agent.is_migrated(staker_address=self.checksum_address)
        return migrated

    def migrate(self, staker_address: Optional[ChecksumAddress] = None) -> TxReceipt:
        receipt = self.staking_agent.migrate(transacting_power=self.transacting_power, staker_address=staker_address)
        return receipt

    @only_me
    @save_receipt
    def remove_inactive_stake(self, stake: Stake) -> TxReceipt:
        self._ensure_stake_exists(stake)

        # Read on-chain stake and validate
        stake.sync()
        if not stake.status().is_child(Stake.Status.INACTIVE):
            raise ValueError(f"Stake with index {stake.index} is still active")

        receipt = self._remove_inactive_stake(stake_index=stake.index)

        # Update staking cache element
        self.refresh_stakes()
        return receipt

    @only_me
    @save_receipt
    def _remove_inactive_stake(self, stake_index: int) -> TxReceipt:
        receipt = self.staking_agent.remove_inactive_stake(transacting_power=self.transacting_power,
                                                           stake_index=stake_index)
        return receipt

    def non_withdrawable_stake(self) -> NU:
        staked_amount: NuNits = self.staking_agent.non_withdrawable_stake(staker_address=self.checksum_address)
        return NU.from_units(staked_amount)

    @property
    def last_committed_period(self) -> int:
        period = self.staking_agent.get_last_committed_period(staker_address=self.checksum_address)
        return period

    def mintable_periods(self) -> int:
        """
        Returns number of periods that can be rewarded in the current period. Value in range [0, 2]
        """
        current_period: Period = self.staking_agent.get_current_period()
        previous_period: int = current_period - 1
        current_committed_period: Period = self.staking_agent.get_current_committed_period(staker_address=self.checksum_address)
        next_committed_period: Period = self.staking_agent.get_next_committed_period(staker_address=self.checksum_address)

        mintable_periods: int = 0
        if 0 < current_committed_period <= previous_period:
            mintable_periods += 1
        if 0 < next_committed_period <= previous_period:
            mintable_periods += 1

        return mintable_periods

    #
    # Bonding with Worker
    #
    @only_me
    @save_receipt
    @validate_checksum_address
    def bond_worker(self, worker_address: ChecksumAddress) -> TxReceipt:
        receipt = self.staking_agent.bond_worker(transacting_power=self.transacting_power,
                                                 worker_address=worker_address)
        self._worker_address = worker_address
        return receipt

    @property
    def worker_address(self) -> str:
        if not self._worker_address:
            # TODO: This is broken for StakeHolder with different stakers - See #1358
            worker_address = self.staking_agent.get_worker_from_staker(staker_address=self.checksum_address)
            self._worker_address = worker_address

        return self._worker_address

    @only_me
    @save_receipt
    def unbond_worker(self) -> TxReceipt:
        receipt = self.staking_agent.release_worker(transacting_power=self.transacting_power)
        self._worker_address = NULL_ADDRESS
        return receipt

    #
    # Reward and Collection
    #

    @only_me
    @save_receipt
    def mint(self) -> TxReceipt:
        """Computes and transfers tokens to the staker's account"""
        receipt = self.staking_agent.mint(transacting_power=self.transacting_power)
        return receipt

    def calculate_staking_reward(self) -> NU:
        staking_reward = self.staking_agent.calculate_staking_reward(staker_address=self.checksum_address)
        return NU.from_units(staking_reward)

    def calculate_policy_fee(self) -> int:
        policy_fee = self.policy_agent.get_fee_amount(staker_address=self.checksum_address)
        return policy_fee

    @only_me
    @save_receipt
    @validate_checksum_address
    def collect_policy_fee(self, collector_address=None) -> TxReceipt:
        """Collect fees (ETH) earned since last withdrawal"""
        withdraw_address = collector_address or self.checksum_address
        receipt = self.policy_agent.collect_policy_fee(collector_address=withdraw_address,
                                                       transacting_power=self.transacting_power)
        return receipt

    @only_me
    @save_receipt
    def collect_staking_reward(self, replace: bool = False) -> TxReceipt:  # TODO: Support replacement for all actor transactions
        """Withdraw tokens rewarded for staking"""
        receipt = self.staking_agent.collect_staking_reward(transacting_power=self.transacting_power, replace=replace)
        return receipt

    @only_me
    @save_receipt
    def withdraw(self, amount: NU, replace: bool = False) -> TxReceipt:
        """Withdraw tokens from StakingEscrow (assuming they're unlocked)"""
        receipt = self.staking_agent.withdraw(transacting_power=self.transacting_power,
                                              amount=NuNits(int(amount)),
                                              replace=replace)
        return receipt

    @property
    def missing_commitments(self) -> int:
        staker_address = self.checksum_address
        missing = self.staking_agent.get_missing_commitments(checksum_address=staker_address)
        return missing

    @only_me
    @save_receipt
    def set_min_fee_rate(self, min_rate: int) -> TxReceipt:
        """Public facing method for staker to set the minimum acceptable fee rate for their associated worker"""
        minimum, _default, maximum = self.policy_agent.get_fee_rate_range()
        if min_rate < minimum or min_rate > maximum:
            raise ValueError(f"Minimum fee rate {min_rate} must fall within global fee range of [{minimum}, {maximum}]")
        receipt = self.policy_agent.set_min_fee_rate(transacting_power=self.transacting_power, min_rate=min_rate)
        return receipt

    @property
    def min_fee_rate(self) -> int:
        """Minimum fee rate that staker accepts"""
        staker_address = self.checksum_address
        min_fee = self.policy_agent.get_min_fee_rate(staker_address)
        return min_fee

    @property
    def raw_min_fee_rate(self) -> int:
        """Minimum acceptable fee rate set by staker for their associated worker.
        This fee rate is only used if it falls within the global fee range.
        If it doesn't a default fee rate is used instead of the raw value (see `min_fee_rate`)"""
        staker_address = self.checksum_address
        min_fee = self.policy_agent.get_raw_min_fee_rate(staker_address)
        return min_fee


class Operator(BaseActor):

    READY_TIMEOUT = None  # (None or 0) == indefinite
    READY_POLL_RATE = 10

    class OperatorError(BaseActor.ActorError):
        pass

    def __init__(self,
                 is_me: bool,
                 work_tracker: WorkTracker = None,
                 operator_address: ChecksumAddress = None,
                 *args, **kwargs):

        super().__init__(*args, **kwargs)
        self.log = Logger("worker")
        self.is_me = is_me
        self.__operator_address = operator_address
        self.__staking_provider_address = None  # set by block_until_ready
        if is_me:
            self.application_agent = ContractAgency.get_agent(PREApplicationAgent, registry=self.registry)
            self.work_tracker = work_tracker or WorkTracker(worker=self)

    @property
    def operator_address(self):
        return self.__operator_address

    @property
    def wallet_address(self):
        return self.operator_address

    @property
    def staking_provider_address(self):
        if not self.__staking_provider_address:
            self.__staking_provider_address = self.get_staking_provider_address()
        return self.__staking_provider_address

    def get_staking_provider_address(self):
        self.__staking_provider_address = self.application_agent.get_staking_provider_from_operator(self.operator_address)
        self.checksum_address = self.__staking_provider_address
        self.nickname = Nickname.from_seed(self.checksum_address)
        return self.__staking_provider_address

    @property
    def is_confirmed(self):
        return self.application_agent.is_operator_confirmed(self.operator_address)

    def confirm_address(self, fire_and_forget: bool = True) -> Union[TxReceipt, HexBytes]:
        txhash_or_receipt = self.application_agent.confirm_operator_address(self.transacting_power, fire_and_forget=fire_and_forget)
        return txhash_or_receipt

    def block_until_ready(self, poll_rate: int = None, timeout: int = None):
        emitter = StdoutEmitter()
        client = self.application_agent.blockchain.client
        poll_rate = poll_rate or self.READY_POLL_RATE
        timeout = timeout or self.READY_TIMEOUT
        start, funded, bonded = maya.now(), False, False
        while not (funded and bonded):

            if timeout and ((maya.now() - start).total_seconds() > timeout):
                message = f"x Operator was not qualified after {timeout} seconds"
                emitter.message(message, color='red')
                raise self.ActorError(message)

            if not funded:
                # check for funds
                ether_balance = client.get_balance(self.operator_address)
                if ether_balance:
                    # funds found
                    funded, balance = True, Web3.fromWei(ether_balance, 'ether')
                    emitter.message(f"✓ Operator is funded with {balance} ETH", color='green')

            if (not bonded) and (self.get_staking_provider_address() != NULL_ADDRESS):
                bonded = True
                emitter.message(f"✓ Operator {self.operator_address} is bonded to staking provider {self.staking_provider_address}", color='green')
            else:
                emitter.message(f"! Operator {self.operator_address } is not bonded to a staking provider", color='yellow')

            time.sleep(poll_rate)

    def get_work_is_needed_check(self):
        def func(self):
            # we have not confirmed yet
            return not self.is_confirmed
        return func


class BlockchainPolicyAuthor(NucypherTokenActor):
    """Alice base class for blockchain operations, mocking up new policies!"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.application_agent = ContractAgency.get_agent(PREApplicationAgent, registry=self.registry)

    def create_policy(self, *args, **kwargs):
        """Hence the name, a BlockchainPolicyAuthor can create a BlockchainPolicy with themself as the author."""
        from nucypher.policy.policies import BlockchainPolicy
        blockchain_policy = BlockchainPolicy(publisher=self, *args, **kwargs)
        return blockchain_policy


class Investigator(NucypherTokenActor):
    """
    Actor that reports incorrect CFrags to the Adjudicator contract.
    In most cases, Bob will act as investigator, but the actor is generic enough than
    anyone can report CFrags.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.adjudicator_agent = ContractAgency.get_agent(AdjudicatorAgent, registry=self.registry)

    @save_receipt
    def request_evaluation(self, evidence) -> dict:
        receipt = self.adjudicator_agent.evaluate_cfrag(evidence=evidence, transacting_power=self.transacting_power)
        return receipt

    def was_this_evidence_evaluated(self, evidence) -> bool:
        result = self.adjudicator_agent.was_this_evidence_evaluated(evidence=evidence)
        return result


class StakeHolder:
    banner = STAKEHOLDER_BANNER

    class UnknownAccount(KeyError):
        pass

    def __init__(self,
                 signer: Signer,
                 registry: BaseContractRegistry,
                 domain: str,
                 initial_address: str = None,
                 worker_data: dict = None):

        self.worker_data = worker_data
        self.log = Logger(f"stakeholder")
        self.checksum_address = initial_address
        self.registry = registry
        self.domain = domain
        self.staker = None
        self.signer = signer

        if initial_address:
            # If an initial address was passed,
            # it is safe to understand that it has already been used at a higher level.
            if initial_address not in self.signer.accounts:
                message = f"Account {initial_address} is not known by this Ethereum client. Is it a HW account? " \
                          f"If so, make sure that your device is plugged in and you use the --hw-wallet flag."
                raise self.UnknownAccount(message)
            self.assimilate(checksum_address=initial_address)

    @validate_checksum_address
    def assimilate(self, checksum_address: ChecksumAddress, password: str = None) -> None:
        original_form = self.checksum_address
        staking_address = checksum_address
        self.checksum_address = staking_address
        self.staker = self.get_staker(checksum_address=staking_address)
        self.staker.refresh_stakes()
        if password:
            self.signer.unlock_account(account=checksum_address, password=password)
        new_form = self.checksum_address
        self.log.info(f"Setting Staker from {original_form} to {new_form}.")

    @validate_checksum_address
    def get_staker(self, checksum_address: ChecksumAddress):
        if checksum_address not in self.signer.accounts:
            raise ValueError(f"{checksum_address} is not a known client account.")
        transacting_power = TransactingPower(account=checksum_address, signer=self.signer)
        staker = Staker(transacting_power=transacting_power,
                        domain=self.domain,
                        registry=self.registry)
        staker.refresh_stakes()
        return staker

    def get_stakers(self) -> List[Staker]:
        stakers = list()
        for account in self.signer.accounts:
            staker = self.get_staker(checksum_address=account)
            stakers.append(staker)
        return stakers

    @property
    def total_stake(self) -> NU:
        """
        The total number of staked tokens, either locked or unlocked in the current period for all stakers
        controlled by the stakeholder's signer.
        """
        staking_agent = ContractAgency.get_agent(StakingEscrowAgent, registry=self.registry)
        stake = sum(staking_agent.owned_tokens(staker_address=account) for account in self.signer.accounts)
        nu_stake = NU.from_units(stake)
        return nu_stake
