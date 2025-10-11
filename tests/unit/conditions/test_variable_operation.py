from decimal import Decimal

import pytest

from nucypher.policy.conditions.exceptions import RequiredContextVariable
from nucypher.policy.conditions.lingo import (
    _OPERATOR_FUNCTIONS,
    _UNARY_OPERATOR_FUNCTIONS,
    VariableOperation,
)

# (Operation, value, initial, expected)
OPERATION_TEST_CASES = [
    ("+=", 2, 3, 5),
    ("-=", 2, 3, 1),
    ("*=", 2, 3, 6),
    ("/=", 2, 6, 3.0),
    ("%=", 2, 5, 1),
    ("^=", 2, 3, 9),
    ("abs", None, -3, 3),
    ("abs", None, 3, 3),
    ("avg", None, [1, 2, 3], 2),
    ("avg", None, [10, 15, 20], 15),
    ("ceil", None, 3.1, 4),
    ("ethToWei", None, 0.000000000000000001, 1),
    ("ethToWei", None, 1.5, 1500000000000000000),
    ("ethToWei", None, 1.1, 1100000000000000000),
    ("floor", None, -3.9, -4),
    ("floor", None, 3.9, 3),
    ("index", 1, [10, 20, 30], 20),
    ("index", 0, [10, 20, 30], 10),
    ("index", 2, [10, 20, 30], 30),
    (
        "index",
        4,
        ["Proper", "preparation", "prevents", "poor", "performance"],
        "performance",
    ),  # -- Ray Lewis
    ("len", None, [1, 2, 3, False, 123.0, "six"], 6),
    ("max", None, [1, 2, 3], 3),
    ("max", None, [123, 25, 35], 123),
    ("min", None, [1, 2, 3], 1),
    ("min", None, [123.4, 50.1, 52], 50.1),
    ("round", 1, 3.1415, 3.1),
    ("round", 2, 3.1415, 3.14),
    ("sum", None, [1, 2, 3], 6),
    ("sum", None, [1232, 22212, 3231], 26675),
    ("weiToEth", None, 1000000000000000000, 1),
    ("weiToEth", None, 1500000000000000000, 1.5),
    ("weiToEth", None, 1100000000000000000, Decimal("1.1")),
    # casting
    ("bool", None, 0, False),
    ("bool", None, 1, True),
    ("bool", None, "", False),
    ("bool", None, [], False),
    ("bool", None, "Non-empty string", True),
    ("float", None, 3, 3.0),
    ("float", None, "123.456", 123.456),
    ("int", None, 3.9, 3),
    ("int", None, "123", 123),
    ("str", None, 123, "123"),
    ("str", None, 123.456, "123.456"),
    (
        "str",
        None,
        "Do not confuse one story for all stories",
        "Do not confuse one story for all stories",
    ),  # -- Anonymous
]


def test_invalid_operation():
    with pytest.raises(ValueError, match="Not a permitted operation"):
        VariableOperation(operation="unknown_op", value=2)


@pytest.mark.parametrize("operation", [op for op, *_ in OPERATION_TEST_CASES])
def test_invalid_operation_and_value_combination(operation):
    if operation in _UNARY_OPERATOR_FUNCTIONS:
        with pytest.raises(ValueError, match="No value should be provided"):
            VariableOperation(operation=operation, value=2)
    else:
        with pytest.raises(ValueError, match="A value must be provided"):
            VariableOperation(operation=operation)


def test_all_operations_covered():
    tested_operations = [op for op, *_ in OPERATION_TEST_CASES]
    assert set(tested_operations) == _OPERATOR_FUNCTIONS.keys()


@pytest.mark.parametrize("operation", [op for op, *_ in OPERATION_TEST_CASES])
def test_type_errors_in_calc(operation):
    value = (
        [
            "random",
            "list",
            "that",
            "doesn't",
            "make",
            "sense",
            "for",
            "most",
            "operations",
        ],
    )

    if operation in _UNARY_OPERATOR_FUNCTIONS:
        op = VariableOperation(operation=operation)
    else:
        op = VariableOperation(operation=operation, value=value)
    # Skip type error test for bool and str casting operations because
    # they can handle any input without raising TypeError
    if operation in ["bool", "str"]:
        return

    with pytest.raises(TypeError):
        if operation in ["int", "float"]:
            op.calc(["some", "list"])
        elif operation in ["%=", "len", "max", "min"]:
            # special cases where the functions can handle strings as the initial variable value
            op.calc(10)
        else:
            op.calc("initial_value_that_does_not_make_sense")


@pytest.mark.parametrize("operation,value,initial,expected", OPERATION_TEST_CASES)
def test_variable_operation_calc(operation, value, initial, expected):
    op = VariableOperation(operation=operation, value=value)
    result = op.calc(initial)
    assert result == expected


def test_cascading_operations():
    initial = [5, 6, 10, 20]
    operations = [
        VariableOperation(operation="index", value=2),  # 10
        VariableOperation(operation="-=", value=2),  # 8
        VariableOperation(operation="*=", value=3),  # 24
        VariableOperation(operation="/=", value=4),  # 6
        VariableOperation(operation="+=", value=10),  # 16
        VariableOperation(operation="%=", value=9),  # 7
        VariableOperation(operation="^=", value=2),  # 49
        VariableOperation(operation="abs"),  # 49
    ]
    result = VariableOperation.calc_from_list(operations, initial)
    assert result == 49


def test_cascading_float_operations():
    initial = 0
    operations = [
        VariableOperation(operation="+=", value=0.1),  # 0.1
        VariableOperation(operation="+=", value=0.1),  # 0.2
        VariableOperation(operation="+=", value=0.1),  # 0.3
        VariableOperation(operation="-=", value=0.3),  # 0
    ]
    result = VariableOperation.calc_from_list(operations, initial)
    assert result == 0


def test_overloaded_operators():
    initial = []
    operations = [
        VariableOperation(operation="+=", value=["T"]),  # T
        VariableOperation(operation="+=", value=["A"]),  # TA
        VariableOperation(operation="+=", value=["C"]),  # TAC
        VariableOperation(operation="+=", value=["o"]),  # TACo
    ]
    result = VariableOperation.calc_from_list(operations, initial)
    assert result == ["T", "A", "C", "o"]

    initial = ""
    operations = [
        VariableOperation(operation="+=", value="T"),  # T
        VariableOperation(operation="+=", value="A"),  # TA
        VariableOperation(operation="+=", value="C"),  # TAC
        VariableOperation(operation="+=", value="o"),  # TACo
    ]
    result = VariableOperation.calc_from_list(operations, initial)
    assert result == "TACo"

    initial = "TACo"
    operations = [
        VariableOperation(operation="*=", value=3),  # TACoTACoTACo
        VariableOperation(operation="+=", value="!"),  # TACoTACoTACo!
    ]
    result = VariableOperation.calc_from_list(operations, initial)
    assert result == "TACoTACoTACo!"


def test_context_variable_resolution_in_operations():
    # various operations with context variables
    initial = 10
    context = {":increment": 5, ":multiplier": 3}
    operations = [
        VariableOperation(operation="+=", value=":increment"),  # 15
        VariableOperation(operation="*=", value=":multiplier"),  # 45
        VariableOperation(operation="-=", value=10),  # 35
    ]

    with pytest.raises(RequiredContextVariable):
        VariableOperation.with_resolved_context(
            operations, context={}
        )  # missing context variables

    resolved_operations = VariableOperation.with_resolved_context(operations, **context)
    result = VariableOperation.calc_from_list(resolved_operations, initial)
    assert result == 35
