import pytest

from nucypher.policy.conditions.lingo import (
    _OPERATOR_FUNCTIONS,
    VariableOperation,
    VariableOperations,
)

OPERATION_TEST_CASES = [
    ("+=", 2, 3, 5),
    ("-=", 2, 3, 1),
    ("*=", 2, 3, 6),
    ("/=", 2, 6, 3.0),
    ("%=", 2, 5, 1),
    ("^=", 2, 3, 9),
    ("avg", None, [1, 2, 3], 2),
    ("avg", None, [10, 15, 20], 15),
    ("ceil", None, 3.1, 4),
    ("floor", None, 3.9, 3),
    ("index", 1, [10, 20, 30], 20),
    ("index", 0, [10, 20, 30], 10),
    ("index", 2, [10, 20, 30], 30),
    ("len", None, [1, 2, 3, False, 123.0, "six"], 6),
    ("max", None, [1, 2, 3], 3),
    ("max", None, [123, 25, 35], 123),
    ("median", None, [1, 2, 3], 2),
    ("median", None, [24, 16, 36, 67], 30),
    ("min", None, [1, 2, 3], 1),
    ("min", None, [123.4, 50.1, 52], 50.1),
    ("mode", None, [1, 1, 2, 2, 5, 6, 7, 8, 0, 1, 1], 1),
    ("round", 1, 3.1415, 3.1),
    ("round", 2, 3.1415, 3.14),
    ("sum", None, [1, 2, 3], 6),
    ("sum", None, [1232, 22212, 3231], 26675),
]


@pytest.mark.parametrize("operation,value,initial,expected", OPERATION_TEST_CASES)
def test_variable_operation_calc(operation, value, initial, expected):
    op = VariableOperation(operation=operation, value=value)
    result = op.calc(initial)
    assert result == expected


def test_all_operations_covered():
    tested_operations = [op for op, *_ in OPERATION_TEST_CASES]
    assert set(tested_operations) == _OPERATOR_FUNCTIONS.keys()


def test_cascading_operations():
    initial = [5, 6, 10, 20]
    operations = VariableOperations(
        [
            VariableOperation(operation="index", value=2),  # 10
            VariableOperation(operation="-=", value=2),  # 8
            VariableOperation(operation="*=", value=3),  # 24
            VariableOperation(operation="/=", value=4),  # 6
            VariableOperation(operation="+=", value=10),  # 16
            VariableOperation(operation="%=", value=9),  # 7
            VariableOperation(operation="^=", value=2),  # 49
        ]
    )
    result = operations.calc(initial)
    assert result == 49


def test_invalid_operation_inputs():
    with pytest.raises(ValueError, match="Not a permitted operation"):
        VariableOperation(operation="unknown_op", value=2)

    with pytest.raises(ValueError, match="At least one operation required"):
        VariableOperations([])  # Empty operations list
