import copy
import json
import os
import random
from typing import Any, Dict, List, Optional, Sequence
from unittest.mock import Mock

import pytest
from hexbytes import HexBytes
from marshmallow import post_load
from web3.providers import BaseProvider

from nucypher.policy.conditions.evm import ContractCondition
from nucypher.policy.conditions.exceptions import InvalidCondition
from nucypher.policy.conditions.types import ContextDict

CHAIN_ID = 137

CONTRACT_CONDITION = {
    "conditionType": "contract",
    "contractAddress": "0x01B67b1194C75264d06F808A921228a95C765dd7",
    "method": "isSubscribedToToken",
    "parameters": ["0x5082F249cDb2f2c1eE035E4f423c46EA2daB3ab1", "subscriptionCode", 4],
    "functionAbi": {
        "inputs": [
            {"internalType": "address", "name": "subscriber", "type": "address"},
            {"internalType": "bytes32", "name": "subscriptionCode", "type": "bytes32"},
            {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
        ],
        "name": "isSubscribedToToken",
        "outputs": [{"internalType": "bool", "name": "valid", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
        "constant": True,
    },
    "chain": CHAIN_ID,
    "returnValueTest": {"comparator": "==", "value": True},
}


class FakeExecutionContractCondition(ContractCondition):
    class Schema(ContractCondition.Schema):
        @post_load
        def make(self, data, **kwargs):
            return FakeExecutionContractCondition(**data)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.execution_return_value = None

    def set_execution_return_value(self, value: Any):
        self.execution_return_value = value

    def _execute_call(self, parameters: List[Any]) -> Any:
        return self.execution_return_value

    def _configure_provider(self, provider: BaseProvider):
        return


@pytest.fixture(scope="function")
def contract_condition_dict():
    return copy.deepcopy(CONTRACT_CONDITION)


def _replace_abi_outputs(condition_json: Dict, output_type: str, output_value: Any):
    # modify outputs type
    condition_json["functionAbi"]["outputs"][0]["internalType"] = output_type
    condition_json["functionAbi"]["outputs"][0]["type"] = output_type

    # modify return value test
    condition_json["returnValueTest"]["value"] = output_value


def _check_execution_logic(
    condition_dict: Dict,
    execution_result: Any,
    comparator_value: Any,
    comparator: str,
    expected_outcome: bool,
    comparator_index: Optional[int] = None,
    context: Optional[ContextDict] = None,
):
    # test execution logic for bool
    condition_dict["returnValueTest"]["value"] = comparator_value
    condition_dict["returnValueTest"]["comparator"] = comparator
    if comparator_index is not None:
        condition_dict["returnValueTest"]["index"] = comparator_index

    fake_execution_contract_condition = FakeExecutionContractCondition.from_json(
        json.dumps(condition_dict)
    )
    fake_execution_contract_condition.set_execution_return_value(execution_result)
    fake_providers = {CHAIN_ID: {Mock(BaseProvider)}}
    context = context or dict()
    condition_result, call_result = fake_execution_contract_condition.verify(
        fake_providers, **context
    )
    assert call_result == execution_result
    assert condition_result == expected_outcome


def test_abi_bool_output(contract_condition_dict):
    # default - no changes to json
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, bool)

    # invalid type fails
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["value"] = 23
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # test execution logic
    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=False,
        comparator_value=False,
        comparator="==",
        expected_outcome=True,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=False,
        comparator_value=False,
        comparator="!=",
        expected_outcome=False,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=True,
        comparator_value=False,
        comparator="==",
        expected_outcome=False,
    )


def test_abi_uint_output(contract_condition_dict):
    _replace_abi_outputs(contract_condition_dict, "uint256", 123456789)
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, int)

    # invalid type fails
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["value"] = True
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # test execution logic
    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=123456789,
        comparator_value=123456789,
        comparator="==",
        expected_outcome=True,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=1,
        comparator_value=123456789,
        comparator="!=",
        expected_outcome=True,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=1,
        comparator_value=2,
        comparator="==",
        expected_outcome=False,
    )


def test_abi_int_output(contract_condition_dict):
    _replace_abi_outputs(contract_condition_dict, "int256", -123456789)
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, int)

    # invalid type fails
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["value"] = [1, 2, 3]
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # test execution logic
    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=-123456789,
        comparator_value=-123456789,
        comparator="==",
        expected_outcome=True,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=-1,
        comparator_value=1,
        comparator="!=",
        expected_outcome=True,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=-1,
        comparator_value=-1,
        comparator="!=",
        expected_outcome=False,
    )


def test_abi_address_output(contract_condition_dict, get_random_checksum_address):
    _replace_abi_outputs(
        contract_condition_dict, "address", get_random_checksum_address()
    )
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, str)

    # invalid type fails
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["value"] = 1.25
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # test execution logic
    checksum_address = get_random_checksum_address()
    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=checksum_address,
        comparator_value=checksum_address,
        comparator="==",
        expected_outcome=True,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=checksum_address,
        comparator_value=checksum_address,
        comparator="!=",
        expected_outcome=False,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=checksum_address,
        comparator_value=get_random_checksum_address(),
        comparator="==",
        expected_outcome=False,
    )


@pytest.mark.parametrize(
    "bytes_test_scenario",
    [
        # bytes type, bytes length to use
        ("bytes1", 1),
        ("bytes16", 16),
        ("bytes32", 32),
        ("bytes", random.randint(1, 96)),  # random number
    ],
)
def test_abi_bytes_output(bytes_test_scenario, contract_condition_dict):
    bytes_type, bytes_length = bytes_test_scenario

    call_result_in_bytes = os.urandom(bytes_length)
    comparator_value_in_hex = HexBytes(
        call_result_in_bytes
    ).hex()  # use hex str for bytes

    _replace_abi_outputs(contract_condition_dict, bytes_type, comparator_value_in_hex)

    # valid condition
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, str)

    # invalid type fails
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["value"] = 1.25
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # test execution logic
    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=call_result_in_bytes,
        comparator_value=comparator_value_in_hex,
        comparator="==",
        expected_outcome=True,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=call_result_in_bytes,
        comparator_value=comparator_value_in_hex,
        comparator="!=",
        expected_outcome=False,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=call_result_in_bytes,
        comparator_value=HexBytes(os.urandom(bytes_length)).hex(),
        comparator="==",
        expected_outcome=False,
    )


def test_abi_tuple_output(contract_condition_dict):
    contract_condition_dict["functionAbi"]["outputs"] = [
        {"internalType": "uint96", "name": "tStake", "type": "uint96"},
        {"internalType": "uint96", "name": "keepInTStake", "type": "uint96"},
        {"internalType": "uint96", "name": "nuInTStake", "type": "uint96"},
        {"internalType": "bytes", "name": "randoBytes", "type": "bytes"},
    ]

    random_bytes = os.urandom(16)
    random_bytes_hex = HexBytes(random_bytes).hex()

    contract_condition_dict["returnValueTest"]["value"] = [1, 2, 3, random_bytes_hex]

    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, Sequence)

    # 1. invalid type
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["value"] = 1
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # 2. invalid number of values
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["value"] = [1, 2]
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # 3a. Unmatched type
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["value"] = [True, 2, 3]
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # 3b. Unmatched type
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["value"] = [1, False, 3]
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # 3c. Unmatched type
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["value"] = [1, 2, 3.14159]
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # test execution logic (tuples are serialized as lists for comparator_value)
    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=(1, 2, 3, random_bytes),
        comparator_value=[1, 2, 3, random_bytes_hex],
        comparator="==",
        expected_outcome=True,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=(2, 3, 4, random_bytes),
        comparator_value=[2, 3, 4, random_bytes_hex],
        comparator="!=",
        expected_outcome=False,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=(3, 4, 5, random_bytes),
        comparator_value=[3, 4, 6, random_bytes_hex],
        comparator="==",
        expected_outcome=False,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=(3, 4, 5, random_bytes),
        comparator_value=[3, 4, 5, HexBytes(os.urandom(16)).hex()],
        comparator="==",
        expected_outcome=False,
    )

    # test using context var
    context = {":myContextVar": [1, 2, 3, random_bytes_hex]}
    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=(1, 2, 3, random_bytes),
        comparator_value=":myContextVar",
        comparator="==",
        expected_outcome=True,
        comparator_index=None,
        context=context,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=(1, 2, 3, random_bytes),
        comparator_value=":myContextVar",
        comparator="!=",
        expected_outcome=False,
        comparator_index=None,
        context=context,
    )

    # test where context var has invalid expected types - boolean is unexpected
    context = {":myContextVar": [1, True, 3, random_bytes_hex]}
    with pytest.raises(InvalidCondition):
        _check_execution_logic(
            condition_dict=contract_condition_dict,
            execution_result=(1, 2, 3, random_bytes),
            comparator_value=":myContextVar",
            comparator="==",
            expected_outcome=True,
            comparator_index=None,
            context=context,
        )


def test_abi_tuple_output_with_index(
    mocker, contract_condition_dict, get_random_checksum_address
):
    contract_condition_dict["functionAbi"]["outputs"] = [
        {"internalType": "uint96", "name": "tStake", "type": "uint96"},
        {"internalType": "uint96", "name": "hasKeep", "type": "bool"},
        {"internalType": "uint96", "name": "nuAddress", "type": "address"},
        {"internalType": "bytes", "name": "randoBytes", "type": "bytes"},
    ]

    random_bytes = os.urandom(16)
    random_bytes_hex = HexBytes(random_bytes).hex()

    # without index
    contract_condition_dict["returnValueTest"]["value"] = [
        1,
        True,
        get_random_checksum_address(),
        random_bytes_hex,
    ]
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, Sequence)

    # index 0
    contract_condition_dict["returnValueTest"]["index"] = 0
    contract_condition_dict["returnValueTest"]["value"] = 1
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, int)

    # index 1
    contract_condition_dict["returnValueTest"]["index"] = 1
    contract_condition_dict["returnValueTest"]["value"] = True
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, bool)

    # index 2
    contract_condition_dict["returnValueTest"]["index"] = 2
    contract_condition_dict["returnValueTest"]["value"] = get_random_checksum_address()
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, str)

    # index 3
    contract_condition_dict["returnValueTest"]["index"] = 3
    contract_condition_dict["returnValueTest"]["value"] = random_bytes_hex
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, str)

    # invalid type at index
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        contract_condition_dict["returnValueTest"]["index"] = 0
        contract_condition_dict["returnValueTest"][
            "value"
        ] = get_random_checksum_address()
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # test execution logic with index for tuples
    result = [1, True, get_random_checksum_address(), random_bytes]
    for i in range(len(result)):
        comparator_value = result[i]
        if comparator_value == random_bytes:
            comparator_value = random_bytes_hex

        _check_execution_logic(
            condition_dict=contract_condition_dict,
            execution_result=tuple(result),
            comparator_value=comparator_value,
            comparator="==",
            expected_outcome=True,
            comparator_index=i,
        )

        _check_execution_logic(
            condition_dict=contract_condition_dict,
            execution_result=tuple(result),
            comparator_value=comparator_value,
            comparator="!=",
            expected_outcome=False,
            comparator_index=i,
        )


def test_abi_multiple_output_values(
    contract_condition_dict, get_random_checksum_address
):
    contract_condition_dict["functionAbi"] = {
        "inputs": [
            {"internalType": "address", "name": "subscriber", "type": "address"},
            {
                "internalType": "bytes32",
                "name": "subscriptionCode",
                "type": "bytes32",
            },
            {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
        ],
        "name": "isSubscribedToToken",
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {
                        "name": "sponsor",
                        "type": "address",
                        "internalType": "address payable",
                    },
                    {
                        "name": "startTimestamp",
                        "type": "uint32",
                        "internalType": "uint32",
                    },
                    {
                        "name": "endTimestamp",
                        "type": "uint32",
                        "internalType": "uint32",
                    },
                    {"name": "size", "type": "uint16", "internalType": "uint16"},
                    {"name": "randoBytes", "type": "bytes", "internalType": "bytes"},
                ],
                "internalType": "struct SubscriptionManager.Policy",
            },
            {
                "name": "valid",
                "type": "bool",
                "internalType": "bool",
            },
            {
                "name": "randoValue",
                "type": "uint256",
                "internalType": "uint256",
            },
        ],
        "stateMutability": "view",
        "type": "function",
        "constant": True,
    }
    contract_condition_dict["returnValueTest"] = {
        "comparator": "==",
        "value": True,
        "index": 1,
    }

    random_bytes = os.urandom(16)
    random_bytes_hex = HexBytes(random_bytes).hex()

    # process index 0 (tuple)
    contract_condition_dict["returnValueTest"]["index"] = 0
    contract_condition_dict["returnValueTest"]["value"] = [
        get_random_checksum_address(),
        1,
        2,
        3,
        random_bytes_hex,
    ]
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, Sequence)

    # process index 1 (bool)
    contract_condition_dict["returnValueTest"]["index"] = 1
    contract_condition_dict["returnValueTest"]["value"] = False
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, bool)

    # process index 2 (int)
    contract_condition_dict["returnValueTest"]["index"] = 2
    contract_condition_dict["returnValueTest"]["value"] = 123456789
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, int)

    # test execution logic - multiple outputs including tuples
    result = [
        [get_random_checksum_address(), 1, 2, 3, random_bytes],
        True,
        4,
    ]
    for i in range(len(result)):
        comparator_value = result[i]
        if isinstance(comparator_value, List):
            comparator_value = copy.deepcopy(result[i])
            comparator_value[4] = random_bytes_hex

        _check_execution_logic(
            condition_dict=contract_condition_dict,
            execution_result=tuple(result),
            comparator_value=comparator_value,
            comparator="==",
            expected_outcome=True,
            comparator_index=i,
        )

        _check_execution_logic(
            condition_dict=contract_condition_dict,
            execution_result=tuple(result),
            comparator_value=comparator_value,
            comparator="!=",
            expected_outcome=False,
            comparator_index=i,
        )

    # test without index
    del contract_condition_dict["returnValueTest"]["index"]
    comparator_value = [
        [result[0][0], result[0][1], result[0][2], result[0][3], random_bytes_hex],
        result[1],
        result[2],
    ]
    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=tuple(result),
        comparator_value=comparator_value,
        comparator="==",
        expected_outcome=True,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=tuple(result),
        comparator_value=comparator_value,
        comparator="!=",
        expected_outcome=False,
    )


def test_abi_nested_tuples_output_values(
    contract_condition_dict, get_random_checksum_address
):
    contract_condition_dict["functionAbi"] = {
        "inputs": [
            {"internalType": "address", "name": "subscriber", "type": "address"},
            {
                "internalType": "bytes32",
                "name": "subscriptionCode",
                "type": "bytes32",
            },
            {"internalType": "uint256", "name": "tokenId", "type": "uint256"},
        ],
        "name": "isSubscribedToToken",
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {
                        "name": "sponsor",
                        "type": "address",
                        "internalType": "address payable",
                    },
                    {
                        "name": "",
                        "type": "tuple",
                        "components": [
                            {
                                "name": "startTimestamp",
                                "type": "uint32",
                                "internalType": "uint32",
                            },
                            {
                                "name": "bytesValue",
                                "type": "bytes",
                                "internalType": "bytes",
                            },
                        ],
                        "internalType": "struct SubscriptionManager.Timeframe",
                    },
                    {"name": "owner", "type": "address", "internalType": "address"},
                ],
                "internalType": "struct SubscriptionManager.Policy",
            },
            {
                "name": "valid",
                "type": "bool",
                "internalType": "bool",
            },
        ],
        "stateMutability": "view",
        "type": "function",
        "constant": True,
    }
    contract_condition_dict["returnValueTest"] = {
        "comparator": "==",
        "value": True,
        "index": 1,
    }

    random_bytes = os.urandom(16)
    random_bytes_hex = HexBytes(random_bytes).hex()

    # process index 0 (nested tuples)
    contract_condition_dict["returnValueTest"]["index"] = 0
    contract_condition_dict["returnValueTest"]["value"] = [
        get_random_checksum_address(),
        [1, random_bytes_hex],
        get_random_checksum_address(),
    ]
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, Sequence)

    # invalid if entire tuple not populated
    contract_condition_dict["returnValueTest"]["value"] = [
        get_random_checksum_address(),
        [1],
        get_random_checksum_address(),  # missing tuple value
    ]
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    contract_condition_dict["returnValueTest"]["value"] = [
        get_random_checksum_address(),
        1,
        random_bytes_hex,
        get_random_checksum_address(),  # incorrect tuple value for Timeframe
    ]
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    contract_condition_dict["returnValueTest"]["value"] = [
        get_random_checksum_address(),
        [1, random_bytes_hex, 3],
        get_random_checksum_address(),  # too many values
    ]
    with pytest.raises(InvalidCondition, match="Invalid return value comparison type"):
        ContractCondition.from_json(json.dumps(contract_condition_dict))

    # process index 1 (bool)
    contract_condition_dict["returnValueTest"]["index"] = 1
    contract_condition_dict["returnValueTest"]["value"] = False
    contract_condition = ContractCondition.from_json(
        json.dumps(contract_condition_dict)
    )
    assert isinstance(contract_condition.return_value_test.value, bool)

    # test execution logic with index - nested tuples
    result = [
        [
            get_random_checksum_address(),
            [1, random_bytes],
            get_random_checksum_address(),
        ],
        True,
    ]
    for i in range(len(result)):
        comparator_value = result[i]
        if isinstance(comparator_value, List):
            comparator_value = copy.deepcopy(result[i])
            comparator_value[1] = [1, random_bytes_hex]

        _check_execution_logic(
            condition_dict=contract_condition_dict,
            execution_result=tuple(result),
            comparator_value=comparator_value,
            comparator="==",
            expected_outcome=True,
            comparator_index=i,
        )

        _check_execution_logic(
            condition_dict=contract_condition_dict,
            execution_result=tuple(result),
            comparator_value=comparator_value,
            comparator="!=",
            expected_outcome=False,
            comparator_index=i,
        )

    # test no index
    del contract_condition_dict["returnValueTest"]["index"]
    comparator_value = [
        [result[0][0], [result[0][1][0], random_bytes_hex], result[0][2]],
        True,
    ]
    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=tuple(result),
        comparator_value=comparator_value,
        comparator="==",
        expected_outcome=True,
    )

    _check_execution_logic(
        condition_dict=contract_condition_dict,
        execution_result=tuple(result),
        comparator_value=comparator_value,
        comparator="!=",
        expected_outcome=False,
    )
