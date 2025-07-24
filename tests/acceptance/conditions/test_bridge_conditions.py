import pytest
from enum import Enum

from nucypher.policy.conditions.evm import ContractCondition
from nucypher.policy.conditions.lingo import (
    ConditionVariable,
    ReturnValueTest,
    SequentialCondition,
)
from nucypher.policy.conditions.signing.base import (
    SIGNING_CONDITION_OBJECT_CONTEXT_VAR,
    AbiCallValidation,
    AbiParameterValidation,
    SigningObjectAbiAttributeCondition,
)
from tests.constants import TESTERCHAIN_CHAIN_ID


class IntentStatus(Enum):
    INACTIVE = 0
    AWAITING_EXECUTION = 1
    EXECUTED = 2
    CANCELLED = 3


class OrderStatus(Enum):
    INACTIVE = 0
    AWAITING_FULFILLMENT = 1
    REFUNDED = 2


def test_bridge_destination_contract_simple(
    bridge_destination_contract, condition_providers
):
    """Simple test to verify bridge destination contract deployment and basic functionality."""

    # Test getOrderID function
    condition = ContractCondition(
        contract_address=bridge_destination_contract.address,
        chain=TESTERCHAIN_CHAIN_ID,
        function_abi={
            "name": "getOrderID",
            "type": "function",
            "inputs": [{"name": "intentId", "type": "uint256"}],
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view",
        },
        method="getOrderID",
        parameters=[1],  # Use intent ID 1 which we set up in the contract
        return_value_test=ReturnValueTest(comparator=">=", value=0),
    )

    # Verify the condition
    allowed, result = condition.verify(providers=condition_providers)
    assert allowed is True, f"Condition should be allowed, but got result: {result}"
    assert result == 1, f"Expected order ID 1, but got: {result}"


def test_bridge_origin_contract_simple(bridge_origin_contract, condition_providers):
    """Simple test to verify bridge origin contract deployment and basic functionality."""

    # Test getRequesterAddress function
    condition = ContractCondition(
        contract_address=bridge_origin_contract.address,
        chain=TESTERCHAIN_CHAIN_ID,
        function_abi={
            "name": "getRequesterAddress",
            "type": "function",
            "inputs": [{"name": "orderId", "type": "uint256"}],
            "outputs": [{"name": "", "type": "address"}],
            "stateMutability": "view",
        },
        method="getRequesterAddress",
        parameters=[1],  # Use order ID 1 which we set up in the contract
        return_value_test=ReturnValueTest(
            comparator="!=", value="0x0000000000000000000000000000000000000000"
        ),
    )

    # Verify the condition
    allowed, result = condition.verify(providers=condition_providers)
    assert allowed is True, f"Condition should be allowed, but got result: {result}"
    assert (
        result == "0xABcdEFABcdEFabcdEfAbCdefabcdeFABcDEFabCD"
    ), f"Expected requester address, but got: {result}"


def test_bridge_fulfiller_execute_intent_condition(
    bridge_destination_contract, bridge_origin_contract, condition_providers, mocker
):
    """Test the bridge fulfiller execute intent condition with deployed contracts."""

    #
    # fulfiller for UserOp for executing the intent (limited to 5 conditions)
    #
    fulfiller_execute_intent_condition = SequentialCondition(
        [
            ConditionVariable(
                var_name="intentID",
                return_index=0,
                condition=SigningObjectAbiAttributeCondition(
                    attribute_name="call_data",
                    abi_validation=AbiCallValidation(
                        {
                            "executeIntent(uint256,address)": [
                                AbiParameterValidation(
                                    parameter_index=0,
                                    return_value_test=ReturnValueTest(">=", 0),
                                ),
                            ]
                        }
                    ),
                ),
            ),  # intentId -> [ID]
            ConditionVariable(
                var_name="orderID",
                condition=ContractCondition(
                    contract_address=bridge_destination_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getOrderID",
                        "type": "function",
                        "inputs": [{"name": "intentId", "type": "uint256"}],
                        "outputs": [{"name": "", "type": "uint256"}],
                        "stateMutability": "view",
                    },
                    method="getOrderID",
                    parameters=[":intentID"],
                    return_value_test=ReturnValueTest(comparator=">=", value=0),
                ),
            ),
            ConditionVariable(
                var_name="requesterAddress",
                condition=ContractCondition(
                    contract_address=bridge_origin_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getRequesterAddress",
                        "type": "function",
                        "inputs": [{"name": "orderId", "type": "uint256"}],
                        "outputs": [{"name": "", "type": "address"}],
                        "stateMutability": "view",
                    },
                    method="getRequesterAddress",
                    parameters=[":orderID"],
                    return_value_test=ReturnValueTest(
                        comparator="!=",
                        value="0x0000000000000000000000000000000000000000",
                    ),
                ),
            ),
            ConditionVariable(
                var_name="intentIDValidation",
                condition=SigningObjectAbiAttributeCondition(
                    attribute_name="call_data",
                    abi_validation=AbiCallValidation(
                        {
                            "executeIntent(uint256,address)": [
                                AbiParameterValidation(
                                    parameter_index=1,
                                    return_value_test=ReturnValueTest(
                                        "==", ":requesterAddress"
                                    ),
                                ),
                            ]
                        }
                    ),
                ),
            ),
            ConditionVariable(
                # destination contract
                var_name="destinationIntentStatus",
                condition=ContractCondition(
                    contract_address=bridge_destination_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getIntentStatus",
                        "type": "function",
                        "inputs": [{"name": "intentId", "type": "uint256"}],
                        "outputs": [{"name": "", "type": "uint8"}],
                        "stateMutability": "view",
                    },
                    method="getIntentStatus",
                    parameters=[":intentID"],
                    return_value_test=ReturnValueTest(
                        comparator="==",
                        value=IntentStatus.AWAITING_EXECUTION.value,
                    ),
                ),
            ),
        ]
    )

    # Mock a signing object with executeIntent call data
    from tests.utils.erc4337 import encode_function_call

    # Create call data for executeIntent(1, requester_address)
    requester_address = (
        "0xABcdEFABcdEFabcdEfAbCdefabcdeFABcDEFabCD"  # This matches our contract setup
    )
    call_data = encode_function_call(
        "executeIntent(uint256,address)",
        [1, requester_address],  # Intent ID 1, with the expected requester address
    )

    signing_object = mocker.Mock()
    signing_object.call_data = call_data
    context = {SIGNING_CONDITION_OBJECT_CONTEXT_VAR: signing_object}

    # Verify the condition
    allowed, result = fulfiller_execute_intent_condition.verify(
        providers=condition_providers, **context
    )

    assert allowed is True, f"Condition should be allowed, but got result: {result}"


def test_bridge_fulfiller_claim_condition(
    bridge_destination_contract, bridge_origin_contract, condition_providers, mocker
):
    """Test the bridge fulfiller claim condition with deployed contracts."""

    #
    # fulfiller claim on origin chain
    #
    fulfiller_claim_condition = SequentialCondition(
        [
            ConditionVariable(
                var_name="orderID",
                condition=SigningObjectAbiAttributeCondition(
                    attribute_name="call_data",
                    abi_validation=AbiCallValidation(
                        {
                            "claimOrder(uint256,address)": [
                                AbiParameterValidation(
                                    parameter_index=0,
                                    return_value_test=ReturnValueTest(">=", 0),
                                ),
                            ]
                        }
                    ),
                ),
            ),  # orderId -> [ID]
            ConditionVariable(
                var_name="intentID",
                condition=ContractCondition(
                    contract_address=bridge_destination_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getIntentID",
                        "type": "function",
                        "inputs": [{"name": "orderId", "type": "uint256"}],
                        "outputs": [{"name": "", "type": "uint256"}],
                        "stateMutability": "view",
                    },
                    method="getIntentID",
                    parameters=":orderID",
                    return_value_test=ReturnValueTest(comparator=">", value=0),
                ),
            ),
            ConditionVariable(
                var_name="fulfillerAddress",
                condition=ContractCondition(
                    contract_address=bridge_destination_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getFulfillerAddress",
                        "type": "function",
                        "inputs": [{"name": "intentId", "type": "uint256"}],
                        "outputs": [{"name": "", "type": "address"}],
                        "stateMutability": "view",
                    },
                    method="getFulfillerAddress",
                    parameters=":intentID",
                    return_value_test=ReturnValueTest(
                        comparator="!=",
                        value="0x0000000000000000000000000000000000000000",
                    ),
                ),
            ),
            ConditionVariable(
                # origin contract
                var_name="originOrderStatus",
                condition=ContractCondition(
                    contract_address=bridge_origin_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getOrderStatus",
                        "type": "function",
                        "inputs": [{"name": "orderId", "type": "uint256"}],
                        "outputs": [{"name": "", "type": "uint8"}],
                        "stateMutability": "view",
                    },
                    method="getOrderStatus",
                    parameters=":orderID",
                    return_value_test=ReturnValueTest(
                        comparator="==",
                        value=OrderStatus.AWAITING_FULFILLMENT.value,
                    ),
                ),
            ),
        ]
    )

    # Mock a signing object with claimOrder call data
    from tests.utils.erc4337 import encode_function_call

    # Create call data for claimOrder(1, fulfiller_address)
    fulfiller_address = (
        "0x1234567890123456789012345678901234567890"  # This matches our contract setup
    )
    call_data = encode_function_call(
        "claimOrder(uint256,address)",
        [1, fulfiller_address],  # Order ID 1, with the expected fulfiller address
    )

    signing_object = mocker.Mock()
    signing_object.call_data = call_data
    context = {SIGNING_CONDITION_OBJECT_CONTEXT_VAR: signing_object}

    # Verify the condition
    allowed, result = fulfiller_claim_condition.verify(
        providers=condition_providers, **context
    )

    assert allowed is True, f"Condition should be allowed, but got result: {result}"
