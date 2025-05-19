import json
from enum import Enum
from typing import NamedTuple, NewType, Optional, TypeVar

from hexbytes import HexBytes

from nucypher.policy.conditions.types import ContextDict
from typing import NamedTuple, NewType, TypeVar

ERC20UNits = NewType("ERC20UNits", int)
NuNits = NewType("NuNits", ERC20UNits)
TuNits = NewType("TuNits", ERC20UNits)

Agent = TypeVar("Agent", bound="agents.EthereumContractAgent")  # noqa: F821

RitualId = int
PhaseNumber = int


class PhaseId(NamedTuple):
    ritual_id: RitualId
    phase: PhaseNumber
