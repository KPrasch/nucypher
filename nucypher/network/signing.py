from typing import Tuple, Union

from hexbytes import HexBytes
from nucypher_core import (
    PackedUserOperation,
    PackedUserOperationSignatureRequest,
    UserOperation,
    UserOperationSignatureRequest,
)

from nucypher.crypto.powers import TransactingPower
from nucypher.utilities.erc4337_utils import sign_packed_user_operation


class UnsupportedSignatureRequest(ValueError):
    """
    Raised for unrecognized signature requests.
    """


def sign_signature_request_data(
    request,
    transacting_power: TransactingPower,
) -> Tuple[HexBytes, HexBytes]:
    """Sign a signature request using the provided transacting power."""
    if isinstance(request, UserOperationSignatureRequest):
        # Special handling for UserOperation requests
        packed_user_operation = PackedUserOperation.from_user_operation(request.user_op)
        return sign_packed_user_operation(
            packed_user_operation,
            transacting_power,
            request.aa_version,
            request.chain_id,
        )
    elif isinstance(request, PackedUserOperationSignatureRequest):
        return sign_packed_user_operation(
            request.packed_user_op,
            transacting_power,
            request.aa_version,
            request.chain_id,
        )

    raise UnsupportedSignatureRequest(
        f"Unsupported signature request: {request.__class__.__name__}"
    )


def get_signature_request_object(
    request: Union[PackedUserOperationSignatureRequest, UserOperationSignatureRequest],
) -> Union[PackedUserOperation, UserOperation]:
    """Get the signature request object based on the request type."""
    if isinstance(request, UserOperationSignatureRequest):
        return request.user_op
    elif isinstance(request, PackedUserOperationSignatureRequest):
        return request.packed_user_op

    raise UnsupportedSignatureRequest(
        f"Unsupported signature request: {request.__class__.__name__}"
    )
