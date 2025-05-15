import json
from typing import NamedTuple, NewType, Optional, TypeVar

from hexbytes import HexBytes

from nucypher.policy.conditions.types import ContextDict

ERC20UNits = NewType("ERC20UNits", int)
NuNits = NewType("NuNits", ERC20UNits)
TuNits = NewType("TuNits", ERC20UNits)

Agent = TypeVar("Agent", bound="agents.EthereumContractAgent")  # noqa: F821

RitualId = int
PhaseNumber = int


class PhaseId(NamedTuple):
    ritual_id: RitualId
    phase: PhaseNumber


class ThresholdSignatureRequest:
    """TODO: Implement this in nucypher_core"""

    def __init__(
        self,
        cohort_id: int,
        chain_id: int,
        data_to_sign: bytes,
        context: Optional[ContextDict] = None,
    ):
        self.cohort_id = cohort_id
        self.chain_id = chain_id
        self.data_to_sign = data_to_sign
        self.context = context or {}

    def __bytes__(self) -> bytes:
        """Serialize the request to bytes in JSON format."""
        data = {
            "cohort_id": self.cohort_id,
            "chain_id": self.chain_id,
            "data_to_sign": self.data_to_sign.hex(),
            "context": self.context,
        }
        return json.dumps(data).encode()

    @staticmethod
    def from_bytes(request_data: bytes):
        result = json.loads(request_data.decode())
        data_to_sign = bytes(HexBytes(result["data_to_sign"]))
        cohort_id = result["cohort_id"]
        chain_id = result["chain_id"]
        context = result["context"]
        return ThresholdSignatureRequest(
            cohort_id=cohort_id,
            chain_id=chain_id,
            data_to_sign=data_to_sign,
            context=context,
        )


class ThresholdSignatureResponse:

    def __init__(self, data: bytes):
        self.data = data

    def __bytes__(self) -> bytes:
        """Serialize the response to bytes in JSON format."""
        return self.data

    @staticmethod
    def from_bytes(response_data: bytes):
        """Deserialize the response from bytes in JSON format."""
        return ThresholdSignatureResponse(data=response_data)
