import json
from typing import Optional

from hexbytes import HexBytes

from nucypher.policy.conditions.types import ContextDict


class ThresholdSignatureRequest:
    """TODO: Implement this in nucypher_core"""

    def __init__(
        self,
        data_to_sign: bytes,
        cohort_id: int,
        context: Optional[ContextDict] = None,
    ):
        self.data_to_sign = data_to_sign
        self.cohort_id = cohort_id
        self.context = context or {}

    def __bytes__(self) -> bytes:
        """Serialize the request to bytes in JSON format."""
        data = {
            "data_to_sign": self.data_to_sign.hex(),
            "cohort_id": self.cohort_id,
            "context": self.context,
        }
        return json.dumps(data).encode()

    @staticmethod
    def from_bytes(request_data: bytes):
        result = json.loads(request_data.decode())
        data = bytes(HexBytes(result["data"]))
        cohort_id = result["cohort_id"]
        context = result["context"]
        return SignatureRequest(
            data=data,
            cohort_id=cohort_id,
            context=context,
        )


class SignatureResponse:

    def __init__(self, message: bytes, _hash: bytes, signature: bytes):
        self.message = message
        self.hash = _hash
        self.signature = signature

    def __bytes__(self) -> bytes:
        """Serialize the response to bytes in JSON format."""
        data = {
            "message": self.message.hex(),
            "message_hash": self.hash.hex(),
            "signature": self.signature.hex(),
        }
        return json.dumps(data).encode()

    @classmethod
    def from_bytes(cls, response_data: bytes):
        """Deserialize the response from bytes in JSON format."""
        result = json.loads(response_data.decode())
        _hash = bytes(HexBytes(result["message_hash"]))
        signature = bytes(HexBytes(result["signature"]))
        message = bytes(HexBytes(result["message"]))
        return cls(
            message=message,
            _hash=_hash,
            signature=signature,
        )
