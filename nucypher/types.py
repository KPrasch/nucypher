from typing import NamedTuple, NewType, TypeVar

from eth_typing.evm import ChecksumAddress
from web3.types import Wei

from nucypher.blockchain.eth import agents

ERC20UNits = NewType("ERC20UNits", int)
NuNits = NewType("NuNits", ERC20UNits)
TuNits = NewType("TuNits", ERC20UNits)

Agent = TypeVar("Agent", bound="agents.EthereumContractAgent")


class StakingProviderInfo(NamedTuple):
    operator: ChecksumAddress
    operator_confirmed: bool
    operator_start_timestamp: int


class PolicyInfo(NamedTuple):
    disabled: bool
    sponsor: ChecksumAddress
    owner: ChecksumAddress
    fee_rate: Wei
    start_timestamp: int
    end_timestamp: int

    # reserved but unused fields in the corresponding Solidity structure below
    # reserved_slot_1
    # reserved_slot_2
    # reserved_slot_3
    # reserved_slot_4
    # reserved_slot_5
