import json
from collections import namedtuple
from unittest.mock import Mock

import pytest
from marshmallow import ValidationError
from packaging.version import parse as parse_version

import nucypher
from nucypher.blockchain.eth.constants import NULL_ADDRESS
from nucypher.policy.conditions.context import USER_ADDRESS_CONTEXT
from nucypher.policy.conditions.exceptions import (
    InvalidConditionLingo,
)
from nucypher.policy.conditions.lingo import (
    AnyField,
    AnyLargeIntegerField,
    CompoundCondition,
    ConditionLingo,
    ConditionType,
    ConditionVariable,
    IfThenElseCondition,
    ReturnValueTest,
    SequentialCondition,
)
from nucypher.policy.conditions.signing.base import SIGNING_CONDITION_OBJECT_CONTEXT_VAR
from nucypher.policy.conditions.time import TimeCondition
from tests.constants import INT256_MIN, TESTERCHAIN_CHAIN_ID, UINT256_MAX


@pytest.fixture(scope="module")
def lingo_with_condition():
    return {
        "conditionType": ConditionType.TIME.value,
        "returnValueTest": {"value": 0, "comparator": ">"},
        "method": "blocktime",
        "chain": TESTERCHAIN_CHAIN_ID,
    }


@pytest.fixture(scope="module")
def lingo_with_all_condition_types(get_random_checksum_address):
    time_condition = {
        "conditionType": ConditionType.TIME.value,
        "method": "blocktime",
        "chain": TESTERCHAIN_CHAIN_ID,
        "returnValueTest": {"value": 0, "comparator": ">"},
    }
    contract_condition = {
        "conditionType": ConditionType.CONTRACT.value,
        "chain": TESTERCHAIN_CHAIN_ID,
        "method": "isPolicyActive",
        "parameters": [":hrac"],
        "contractAddress": get_random_checksum_address(),
        "functionAbi": {
            "type": "function",
            "name": "isPolicyActive",
            "stateMutability": "view",
            "inputs": [
                {
                    "name": "_policyID",
                    "type": "bytes16",
                    "internalType": "bytes16",
                }
            ],
            "outputs": [{"name": "", "type": "bool", "internalType": "bool"}],
        },
        "returnValueTest": {"comparator": "==", "value": True},
    }
    rpc_condition = {
        # RPC
        "conditionType": ConditionType.RPC.value,
        "chain": TESTERCHAIN_CHAIN_ID,
        "method": "eth_getBalance",
        "parameters": [
            get_random_checksum_address(),
            "latest",
        ],
        "returnValueTest": {
            "comparator": ">=",
            "value": 10000000000000,
        },
    }
    json_api_condition = {
        # JSON API
        "conditionType": ConditionType.JSONAPI.value,
        "endpoint": "https://api.example.com/data",
        "parameters": {
            "ids": "ethereum",
            "vs_currencies": "usd",
        },
        "authorizationToken": ":authToken",
        "query": "$.store.book[0].price",
        "returnValueTest": {
            "comparator": "==",
            "value": 2,
            "operations": [
                {
                    "operation": "*=",
                    "value": 1,
                },
                {
                    "operation": "-=",
                    "value": 5.5,
                },
            ],
        },
    }
    json_rpc_condition = {
        # JSON RPC
        "conditionType": ConditionType.JSONRPC.value,
        "endpoint": "https://math.example.com/",
        "method": "subtract",
        "params": [42, 23],
        "query": "$.mathresult",
        "returnValueTest": {
            "comparator": "==",
            "value": 19,
        },
    }
    jwt_condition = {
        # JWT
        "conditionType": ConditionType.JWT.value,
        "jwtToken": ":token",
        "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXHVxB7s5SR7I9cWwry/JkECIReka\nCwG3uOLCYbw5gVzn4dRmwMyYUJFcQWuFSfECRK+uQOOXD0YSEucBq0p5tA==\n-----END PUBLIC KEY-----",
    }
    sequential_condition = {
        "conditionType": ConditionType.SEQUENTIAL.value,
        "conditionVariables": [
            {
                "varName": "timeValue",
                "condition": time_condition,
                "operations": [
                    {
                        "operation": "+=",
                        "value": 100_000,
                    }
                ],
            },
            {
                "varName": "rpcValue",
                "condition": rpc_condition,
            },
            {
                "varName": "contractValue",
                "condition": contract_condition,
            },
            {
                "varName": "jsonValue",
                "condition": json_api_condition,
            },
            {
                "varName": "jwtValue",
                "condition": jwt_condition,
            },
        ],
    }
    json_api_condition_w_auth_type = {
        # JSON API
        "conditionType": ConditionType.JSONAPI.value,
        "endpoint": "https://api.example.com/data",
        "parameters": {
            "ids": "ethereum",
            "vs_currencies": "usd",
        },
        "authorizationToken": ":authToken",
        "authorizationType": "Bearer",
        "query": "$.store.book[0].price",
        "returnValueTest": {
            "comparator": "==",
            "value": 2,
        },
    }
    json_rpc_condition_w_auth_type = {
        # JSON RPC
        "conditionType": ConditionType.JSONRPC.value,
        "endpoint": "https://math.example.com/",
        "method": "subtract",
        "params": [42, 23],
        "query": "$.mathresult",
        "authorizationToken": ":authToken",
        "authorizationType": "X-API-Key",
        "returnValueTest": {
            "comparator": "==",
            "value": 19,
            "operations": [
                {
                    "operation": "sum",
                }
            ],
        },
    }
    if_then_else_condition = {
        "conditionType": ConditionType.IF_THEN_ELSE.value,
        "ifCondition": json_rpc_condition,
        "thenCondition": json_api_condition_w_auth_type,
        "elseCondition": json_rpc_condition_w_auth_type,
    }
    signing_object_attribute_condition = {
        "conditionType": ConditionType.SIGNING_ATTRIBUTE.value,
        "signingObjectContextVar": SIGNING_CONDITION_OBJECT_CONTEXT_VAR,
        "attributeName": "sender",
        "returnValueTest": {
            "comparator": "==",
            "value": get_random_checksum_address(),
        },
    }
    signing_object_abi_attribute_condition = {
        "conditionType": ConditionType.SIGNING_ABI_ATTRIBUTE.value,
        "signingObjectContextVar": SIGNING_CONDITION_OBJECT_CONTEXT_VAR,
        "attributeName": "call_data",
        "abiValidation": {
            "allowedAbiCalls": {
                "execute((address,uint256,bytes))": [
                    {
                        "parameterIndex": 0,
                        "indexWithinTuple": 1,
                        "returnValueTest": {
                            "comparator": "<",
                            "value": 1000000000000000,
                        },
                    }
                ]
            }
        },
    }
    context_var_condition = {
        "conditionType": ConditionType.CONTEXT_VARIABLE.value,
        "contextVariable": ":myContextVar",
        "returnValueTest": {
            "comparator": "!=",
            "value": 23,
        },
    }
    return {
        "version": ConditionLingo.VERSION,
        "condition": {
            "conditionType": ConditionType.COMPOUND.value,
            "operator": "and",
            "operands": [
                contract_condition,
                if_then_else_condition,
                sequential_condition,
                rpc_condition,
                {
                    "conditionType": ConditionType.COMPOUND.value,
                    "operator": "at-least",
                    "operands": [
                        signing_object_attribute_condition,
                        signing_object_abi_attribute_condition,
                        context_var_condition,
                    ],
                    "threshold": 1,
                },
            ],
        },
    }

def test_invalid_condition():
    # no version or condition
    data = dict()
    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_dict(data)

    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_json(json.dumps(data))

    # no condition
    data = {"version": ConditionLingo.VERSION}
    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_dict(data)

    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_json(json.dumps(data))

    # invalid condition
    data = {
        "version": ConditionLingo.VERSION,
        "condition": {"dont_mind_me": "nothing_to_see_here"},
    }
    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_dict(data)

    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_json(json.dumps(data))


def test_invalid_compound_condition():

    # invalid operator
    invalid_operator = {
        "version": ConditionLingo.VERSION,
        "condition": {
            "conditionType": ConditionType.COMPOUND.value,
            "operator": "xTrue",
            "operands": [
                {
                    "conditionType": ConditionType.TIME.value,
                    "returnValueTest": {"value": 0, "comparator": ">"},
                    "method": "blocktime",
                    "chain": TESTERCHAIN_CHAIN_ID,
                },
            ],
        },
    }
    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_dict(invalid_operator)

    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_json(json.dumps(invalid_operator))

    # < 2 operands for and condition
    invalid_and_operands_lingo = {
        "version": ConditionLingo.VERSION,
        "condition": {
            "conditionType": ConditionType.COMPOUND.value,
            "operator": "and",
            "operands": [
                {
                    "conditionType": ConditionType.TIME.value,
                    "returnValueTest": {"value": 0, "comparator": ">"},
                    "method": "blocktime",
                    "chain": TESTERCHAIN_CHAIN_ID,
                }
            ],
        },
    }
    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_dict(invalid_and_operands_lingo)

    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_json(json.dumps(invalid_and_operands_lingo))

    # < 2 operands for or condition
    invalid_or_operands_lingo = {
        "version": ConditionLingo.VERSION,
        "condition": {
            "conditionType": ConditionType.COMPOUND.value,
            "operator": "or",
            "operands": [
                {
                    "conditionType": ConditionType.TIME.value,
                    "returnValueTest": {"value": 0, "comparator": ">"},
                    "method": "blocktime",
                    "chain": TESTERCHAIN_CHAIN_ID,
                }
            ],
        },
    }
    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_dict(invalid_or_operands_lingo)

    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_json(json.dumps(invalid_or_operands_lingo))

    # > 1 operand for `not` condition
    invalid_not_operands_lingo = {
        "version": ConditionLingo.VERSION,
        "condition": {
            "conditionType": ConditionType.COMPOUND.value,
            "operator": "not",
            "operands": [
                {
                    "conditionType": ConditionType.TIME.value,
                    "returnValueTest": {"value": 0, "comparator": ">"},
                    "method": "blocktime",
                    "chain": TESTERCHAIN_CHAIN_ID,
                },
                {
                    "conditionType": ConditionType.TIME.value,
                    "returnValueTest": {"value": 99999999999999999, "comparator": "<"},
                    "method": "blocktime",
                    "chain": TESTERCHAIN_CHAIN_ID,
                },
            ],
        },
    }
    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_dict(invalid_not_operands_lingo)

    with pytest.raises(InvalidConditionLingo):
        ConditionLingo.from_json(json.dumps(invalid_not_operands_lingo))


@pytest.mark.parametrize("case", ["major", "minor", "patch"])
def test_invalid_condition_version(case):
    # version in the future
    current_version = parse_version(ConditionLingo.VERSION)
    major = current_version.major
    minor = current_version.minor
    patch = current_version.micro
    if case == "major":
        major += 1
    elif case == "minor":
        minor += 1
    else:
        patch += 1

    newer_version_string = f"{major}.{minor}.{patch}"
    lingo_dict = {
        "version": newer_version_string,
        "condition": {
            "conditionType": ConditionType.TIME.value,
            "returnValueTest": {"value": 0, "comparator": ">"},
            "method": "blocktime",
            "chain": TESTERCHAIN_CHAIN_ID,
        },
    }
    if case == "major":
        # exception should be thrown since incompatible:
        with pytest.raises(InvalidConditionLingo):
            ConditionLingo.from_dict(lingo_dict)

        with pytest.raises(InvalidConditionLingo):
            ConditionLingo.from_json(json.dumps(lingo_dict))
    else:
        # no exception thrown
        _ = ConditionLingo.from_dict(lingo_dict)
        _ = ConditionLingo.from_json(json.dumps(lingo_dict))


def test_condition_lingo_to_from_dict(lingo_with_all_condition_types):
    clingo = ConditionLingo.from_dict(lingo_with_all_condition_types)
    clingo_dict = clingo.to_dict()
    assert clingo_dict == lingo_with_all_condition_types


def test_condition_lingo_to_from_json(lingo_with_all_condition_types):
    # A bit more convoluted because fields aren't
    # necessarily ordered - so string comparison is tricky
    clingo_from_dict = ConditionLingo.from_dict(lingo_with_all_condition_types)
    lingo_json = clingo_from_dict.to_json()

    clingo_from_json = ConditionLingo.from_json(lingo_json)
    assert clingo_from_json.to_dict() == lingo_with_all_condition_types


def test_condition_lingo_to_from_bytes(lingo_with_all_condition_types):
    clingo = ConditionLingo.from_dict(lingo_with_all_condition_types)
    clingo_bytes = bytes(clingo)
    clingo_from_bytes = ConditionLingo.from_bytes(clingo_bytes)
    assert clingo_from_bytes.to_dict() == lingo_with_all_condition_types


def test_condition_lingo_to_from_base64(lingo_with_all_condition_types):
    clingo = ConditionLingo.from_dict(lingo_with_all_condition_types)
    clingo_base64 = clingo.to_base64()
    clingo_from_base64 = ConditionLingo.from_base64(clingo_base64)
    assert clingo_from_base64.to_dict() == lingo_with_all_condition_types


def test_compound_condition_lingo_repr(lingo_with_all_condition_types):
    clingo = ConditionLingo.from_dict(lingo_with_all_condition_types)
    clingo_string = f"{clingo}"
    assert f"{clingo.__class__.__name__}" in clingo_string
    assert f"version={ConditionLingo.VERSION}" in clingo_string
    assert f"id={clingo.id}" in clingo_string
    assert f"size={len(bytes(clingo))}" in clingo_string


def test_lingo_parameter_int_type_preservation(custom_abi_with_multiple_parameters, mocker):
    mocker.patch.dict(
        nucypher.policy.conditions.context._DIRECTIVES,
        {USER_ADDRESS_CONTEXT: lambda: NULL_ADDRESS},
    )
    clingo_json = json.dumps(
        {
            "version": ConditionLingo.VERSION,
            "condition": json.loads(
                custom_abi_with_multiple_parameters  # fixture is already a json string
            ),
        }
    )

    clingo = ConditionLingo.from_json(clingo_json)
    conditions = clingo.to_dict()
    assert conditions["condition"]["parameters"][2] == 4


def test_lingo_resolves_condition_type(lingo_with_condition):
    for condition_type in ConditionType.values():
        lingo_with_condition["conditionType"] = condition_type
        ConditionLingo.resolve_condition_class(lingo_with_condition)


def test_lingo_rejects_invalid_condition_type(lingo_with_condition):
    for condition_type in ["invalid", "", None]:
        lingo_with_condition["conditionType"] = condition_type
        with pytest.raises(InvalidConditionLingo):
            ConditionLingo.resolve_condition_class(lingo_with_condition)


def test_lingo_data(conditions_test_data):
    for name, condition_dict in conditions_test_data.items():
        condition_class = ConditionLingo.resolve_condition_class(condition_dict)
        _ = condition_class.from_dict(condition_dict)


@pytest.mark.parametrize(
    "value",
    [
        1231323123132,
        2121.23211,
        False,
        '"foo"',  # string
        "5555555555",  # example of a number that was a string and should remain a string
        ":userAddress",  # context variable
        "0xaDD9D957170dF6F33982001E4c22eCCdd5539118",  # string
        "0x1234",  # hex string
        125,  # int
        -123456789,  # negative int
        1.223,  # float
        True,  # bool
        [1, 1.2314, False, "love"],  # list of different types
        ["a", "b", "c"],  # list
        [True, False],  # list of bools
        {"name": "John", "age": 22},  # dict
        namedtuple("MyStruct", ["field1", "field2"])(1, "a"),
        [True, 2, 6.5, "0x123"],
    ],
)
def test_any_field_various_types(value):
    field = AnyField()

    deserialized_value = field.deserialize(value)
    serialized_value = field._serialize(deserialized_value, attr=None, obj=None)

    assert deserialized_value == serialized_value
    assert deserialized_value == value


@pytest.mark.parametrize(
    "integer_value",
    [
        UINT256_MAX,
        INT256_MIN,
        123132312,  # safe int
        -1231231,  # safe negative int
    ],
)
def test_any_field_integer_str_and_no_str_conversion(integer_value):
    field = AnyField()

    deserialized_raw_integer = field.deserialize(value=integer_value)
    deserialized_big_int_string = field.deserialize(value=f"{integer_value}n")
    assert deserialized_raw_integer == deserialized_big_int_string

    assert (
        field._serialize(deserialized_raw_integer, attr=None, obj=None) == integer_value
    )
    assert (
        field._serialize(deserialized_big_int_string, attr=None, obj=None)
        == integer_value
    )


def test_any_field_nested_integer():
    field = AnyField()

    regular_number = 12341231

    parameters = [
        f"{UINT256_MAX}n",
        {"a": [f"{INT256_MIN}n", "my_string_value", "0xdeadbeef"], "b": regular_number},
    ]
    # quoted numbers get unquoted after deserialization
    expected_parameters = [
        UINT256_MAX,
        {"a": [INT256_MIN, "my_string_value", "0xdeadbeef"], "b": regular_number},
    ]

    deserialized_parameters = field.deserialize(value=parameters)
    assert deserialized_parameters == expected_parameters


@pytest.mark.parametrize(
    "json_value, expected_deserialized_value",
    [
        (123132312, 123132312),  # safe int
        (-1231231, -1231231),  # safe negative int
        (f"{UINT256_MAX}n", UINT256_MAX),
        (f"{INT256_MIN}n", INT256_MIN),
        (f"{UINT256_MAX*2}n", UINT256_MAX * 2),  # larger than uint256 max
        (f"{INT256_MIN*2}n", INT256_MIN * 2),  # smaller than in256 min
        # expected failures
        ("Totally a number", None),
        ("Totally a number that ends with n", None),
        ("fallen", None),
    ],
)
def test_any_large_integer_field(json_value, expected_deserialized_value):
    field = AnyLargeIntegerField()

    if expected_deserialized_value is not None:
        assert field.deserialize(json_value) == expected_deserialized_value
    else:
        # expected to fail
        with pytest.raises(ValidationError, match="Not a valid integer."):
            _ = field.deserialize(json_value)


class TestEvalWithDetails:
    """Tests for ConditionLingo.eval_with_details() debug method."""

    def test_eval_with_details_success_returns_none_for_failure_details(self):
        """On success, failure_details should be None."""
        # Create a passing time condition (timestamp > 0, always true)
        condition = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 0),
        )
        lingo = ConditionLingo(condition=condition)

        # Mock the condition.verify to return success
        mock_actual_value = 1234567890
        condition.verify = Mock(return_value=(True, mock_actual_value))

        success, actual_value, failure_details = lingo.eval_with_details()

        assert success is True
        assert actual_value == mock_actual_value
        assert failure_details is None

    def test_eval_with_details_failure_returns_debug_info(self):
        """On failure, should return structured debug info."""
        # Create a time condition that will fail
        condition = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 9999999999999),
        )
        lingo = ConditionLingo(condition=condition)

        # Mock the condition.verify to return failure
        mock_actual_value = 1234567890
        condition.verify = Mock(return_value=(False, mock_actual_value))

        success, actual_value, failure_details = lingo.eval_with_details()

        assert success is False
        assert actual_value == mock_actual_value
        assert failure_details is not None
        assert "failed_condition" in failure_details
        assert "actual_value" in failure_details
        assert failure_details["actual_value"] == mock_actual_value
        assert "expected" in failure_details
        assert failure_details["expected"]["comparator"] == ">"
        assert failure_details["expected"]["value"] == 9999999999999
        assert "full_lingo" in failure_details
        assert failure_details["full_lingo"]["version"] == ConditionLingo.VERSION

    def test_eval_with_details_compound_condition_identifies_failed_operand(self):
        """For compound AND, should identify which operand failed."""
        # First condition passes, second fails
        passing_condition = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 0),
        )
        failing_condition = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 9999999999999),
        )

        compound = CompoundCondition(
            operator="and",
            operands=[passing_condition, failing_condition],
        )
        lingo = ConditionLingo(condition=compound)

        # Mock verify to simulate: first passes (True, 1000), second fails (False, 500)
        # CompoundCondition.verify short-circuits on first failure
        compound.verify = Mock(return_value=(False, [1234567890, 500]))

        success, actual_value, failure_details = lingo.eval_with_details()

        assert success is False
        assert "compound_details" in failure_details
        assert failure_details["compound_details"]["operator"] == "and"
        assert len(failure_details["compound_details"]["operand_results"]) >= 1

    def test_eval_with_details_preserves_return_value_test_index(self):
        """If ReturnValueTest has an index, it should be included in expected."""
        condition = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 100, index=0),
        )
        lingo = ConditionLingo(condition=condition)

        # Mock failure
        condition.verify = Mock(return_value=(False, [50, 60, 70]))

        success, actual_value, failure_details = lingo.eval_with_details()

        assert success is False
        assert failure_details["expected"]["index"] == 0

    def test_eval_with_details_sequential_condition_failure(self):
        """For sequential conditions, should extract condition variable details."""
        # Create two time conditions for a sequential condition
        condition1 = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 0),
        )
        condition2 = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 9999999999999),
        )

        # Create condition variables
        cv1 = ConditionVariable(var_name="time1", condition=condition1)
        cv2 = ConditionVariable(var_name="time2", condition=condition2)

        sequential = SequentialCondition(condition_variables=[cv1, cv2])
        lingo = ConditionLingo(condition=sequential)

        # Mock verify to return failure with actual values
        sequential.verify = Mock(return_value=(False, [1234567890, 500]))

        success, actual_value, failure_details = lingo.eval_with_details()

        assert success is False
        assert "sequential_details" in failure_details
        assert "condition_variables" in failure_details["sequential_details"]
        cv_details = failure_details["sequential_details"]["condition_variables"]
        assert len(cv_details) == 2
        assert cv_details[0]["var_name"] == "time1"
        assert cv_details[0]["actual_value"] == 1234567890
        assert cv_details[1]["var_name"] == "time2"
        assert cv_details[1]["actual_value"] == 500

    def test_eval_with_details_if_then_else_condition_failure(self):
        """For if-then-else conditions, should extract branch details."""
        # Create conditions for if-then-else
        if_condition = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 0),
        )
        then_condition = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 9999999999999),
        )
        else_condition = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest("<", 100),
        )

        if_then_else = IfThenElseCondition(
            if_condition=if_condition,
            then_condition=then_condition,
            else_condition=else_condition,
        )
        lingo = ConditionLingo(condition=if_then_else)

        # Mock verify to return failure
        if_then_else.verify = Mock(return_value=(False, [True, 500, None]))

        success, actual_value, failure_details = lingo.eval_with_details()

        assert success is False
        assert "if_then_else_details" in failure_details
        details = failure_details["if_then_else_details"]
        assert "if_condition" in details
        assert "then_condition" in details
        assert "else_condition" in details
        assert "actual_values" in details
        assert details["actual_values"] == [True, 500, None]

    def test_eval_with_details_if_then_else_with_bool_else(self):
        """For if-then-else with boolean else, should handle correctly."""
        if_condition = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 0),
        )
        then_condition = TimeCondition(
            chain=TESTERCHAIN_CHAIN_ID,
            return_value_test=ReturnValueTest(">", 9999999999999),
        )

        if_then_else = IfThenElseCondition(
            if_condition=if_condition,
            then_condition=then_condition,
            else_condition=True,  # boolean else
        )
        lingo = ConditionLingo(condition=if_then_else)

        # Mock verify to return failure
        if_then_else.verify = Mock(return_value=(False, [True, 500]))

        success, actual_value, failure_details = lingo.eval_with_details()

        assert success is False
        assert "if_then_else_details" in failure_details
        details = failure_details["if_then_else_details"]
        # Boolean else should be preserved as-is
        assert details["else_condition"] is True
