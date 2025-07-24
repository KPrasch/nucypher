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


class IntentState(Enum):
    INACTIVE = 0
    AWAITING_EXECUTION = 1
    EXECUTED = 2
    CANCELLED = 3


class OrderState(Enum):
    INACTIVE = 0
    AWAITING_FULFILLMENT = 1
    REFUNDED = 2
    CANCELED = 3
    EXECUTED = 4


def test_bridge_fulfiller_execute_intent_condition(
    orderbook_contract, condition_providers
):
    """Test the complete bridge fulfiller execute intent condition using OrderBook contract."""

    #
    # fulfiller for UserOp for executing the intent
    #
    fulfiller_execute_intent_condition = SequentialCondition(
        [
            ConditionVariable(
                var_name="intentID",
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
                    contract_address=orderbook_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getOrderID",
                        "type": "function",
                        "inputs": [{"name": "intentId", "type": "uint256"}],
                        "outputs": [{"name": "", "type": "uint256"}],
                        "stateMutability": "view",
                    },
                    method="getOrderID",
                    parameters=":intentID",
                    return_value_test=ReturnValueTest(comparator=">=", value=0),
                ),
            ),
            ConditionVariable(
                var_name="requesterAddress",
                condition=ContractCondition(
                    contract_address=orderbook_contract.address,
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
                var_name="destinationIntentStatus",
                condition=ContractCondition(
                    contract_address=orderbook_contract.address,
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
                        value=IntentState.AWAITING_EXECUTION.value,
                    ),
                ),
            ),
            ConditionVariable(
                var_name="destinationIntent",
                condition=ContractCondition(
                    contract_address=orderbook_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getIntent",
                        "type": "function",
                        "inputs": [{"name": "intentId", "type": "uint256"}],
                        "outputs": [
                            {"name": "token", "type": "address"},
                            {"name": "amount", "type": "uint256"},
                        ],
                        "stateMutability": "view",
                    },
                    method="getIntent",
                    parameters=[":intentID"],
                    return_value_test=ReturnValueTest(comparator="!=", value=None),
                ),
            ),
            ConditionVariable(
                var_name="originOrder",
                condition=ContractCondition(
                    contract_address=orderbook_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getOrder",
                        "type": "function",
                        "inputs": [{"name": "orderId", "type": "uint256"}],
                        "outputs": [
                            {"name": "token", "type": "address"},
                            {"name": "amount", "type": "uint256"},
                        ],
                        "stateMutability": "view",
                    },
                    method="getOrder",
                    parameters=[":orderID"],
                    return_value_test=ReturnValueTest(comparator="!=", value=None),
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
        ]
    )

    print("Bridge fulfiller execute intent condition created successfully")
    print(f"OrderBook contract address: {orderbook_contract.address}")


def test_bridge_fulfiller_claim_condition(orderbook_contract, condition_providers):
    """Test the complete bridge fulfiller claim condition using OrderBook contract."""

    # Test the claim side of the bridge functionality
    fulfiller_claim_condition = SequentialCondition(
        [
            ConditionVariable(
                var_name="intentID",
                condition=ContractCondition(
                    contract_address=orderbook_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getIntentID",
                        "type": "function",
                        "inputs": [{"name": "orderId", "type": "uint256"}],
                        "outputs": [{"name": "", "type": "uint256"}],
                        "stateMutability": "view",
                    },
                    method="getIntentID",
                    parameters=[":orderID"],
                    return_value_test=ReturnValueTest(comparator=">", value=0),
                ),
            ),
            ConditionVariable(
                var_name="fulfillerAddress",
                condition=ContractCondition(
                    contract_address=orderbook_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getFulfillerAddress",
                        "type": "function",
                        "inputs": [{"name": "intentID", "type": "uint256"}],
                        "outputs": [{"name": "", "type": "address"}],
                        "stateMutability": "view",
                    },
                    method="getFulfillerAddress",
                    parameters=[":intentID"],
                    return_value_test=ReturnValueTest(
                        comparator="!=",
                        value="0x0000000000000000000000000000000000000000",
                    ),
                ),
            ),
            ConditionVariable(
                var_name="orderStatus",
                condition=ContractCondition(
                    contract_address=orderbook_contract.address,
                    chain=TESTERCHAIN_CHAIN_ID,
                    function_abi={
                        "name": "getOrderStatus",
                        "type": "function",
                        "inputs": [{"name": "orderId", "type": "uint256"}],
                        "outputs": [{"name": "", "type": "uint8"}],
                        "stateMutability": "view",
                    },
                    method="getOrderStatus",
                    parameters=[":orderID"],
                    return_value_test=ReturnValueTest(
                        comparator="==",
                        value=OrderState.AWAITING_FULFILLMENT.value,
                    ),
                ),
            ),
        ]
    )

    print("Bridge fulfiller claim condition created successfully")
    print(f"OrderBook contract address: {orderbook_contract.address}")


def test_orderbook_contract_simple(orderbook_contract, condition_providers):
    """Simple test to verify OrderBook contract deployment and basic functionality."""

    # Test getOrderID function with a basic condition
    condition = ContractCondition(
        contract_address=orderbook_contract.address,
        chain=TESTERCHAIN_CHAIN_ID,
        function_abi={
            "name": "getOrderID",
            "type": "function",
            "inputs": [{"name": "intentId", "type": "uint256"}],
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view",
        },
        method="getOrderID",
        parameters=[0],  # Use intent ID 0
        return_value_test=ReturnValueTest(comparator=">=", value=0),
    )

    # Verify the condition
    allowed, result = condition.verify(providers=condition_providers)
    assert allowed is True, f"Condition should be allowed, but got result: {result}"

    print(f"OrderBook contract deployed successfully at: {orderbook_contract.address}")
    print(f"Test result: {result}")
