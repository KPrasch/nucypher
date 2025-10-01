import json

import pytest

from nucypher.policy.conditions.exceptions import InvalidCondition
from nucypher.policy.conditions.json.json import JsonCondition
from nucypher.policy.conditions.lingo import ConditionLingo, ReturnValueTest


def test_json_condition_initialization():
    data = {"store": {"book": [{"price": 10.5}]}}
    condition = JsonCondition(
        data=data,
        query="$.store.book[0].price",
        return_value_test=ReturnValueTest("==", 10.5),
    )
    assert condition.data == data
    assert condition.query == "$.store.book[0].price"


def test_json_condition_with_json_string():
    json_string = '{"value": 42}'
    condition = JsonCondition(
        data=json_string,
        query="$.value",
        return_value_test=ReturnValueTest("==", 42),
    )
    assert condition.data == {"value": 42}


def test_json_condition_with_primitive():
    condition = JsonCondition(
        data=42,
        return_value_test=ReturnValueTest("==", 42),
    )
    assert condition.data == 42
    assert condition.query is None


def test_json_condition_invalid_type():
    with pytest.raises(
        InvalidCondition, match="'condition_type' field - Must be equal to json"
    ):
        _ = JsonCondition(
            condition_type="INVALID_TYPE",
            data={"test": "data"},
            return_value_test=ReturnValueTest("==", 0),
        )


def test_json_condition_invalid_json_string():
    with pytest.raises(InvalidCondition, match="Invalid JSON string"):
        _ = JsonCondition(
            data='{"invalid": json}',
            return_value_test=ReturnValueTest("==", 0),
        )


def test_json_condition_verify():
    data = {"store": {"book": [{"price": 10.5}]}}
    condition = JsonCondition(
        data=data,
        query="$.store.book[0].price",
        return_value_test=ReturnValueTest("==", 10.5),
    )
    result, value = condition.verify()
    assert result is True
    assert value == 10.5


def test_json_condition_verify_with_string():
    data = {"store": {"book": [{"title": "Test Title"}]}}
    condition = JsonCondition(
        data=data,
        query="$.store.book[0].title",
        return_value_test=ReturnValueTest("==", "'Test Title'"),
    )
    result, value = condition.verify()
    assert result is True
    assert value == "Test Title"


def test_json_condition_verify_primitive_no_query():
    condition = JsonCondition(
        data=100,
        return_value_test=ReturnValueTest(">", 50),
    )
    result, value = condition.verify()
    assert result is True
    assert value == 100


def test_json_condition_with_context_variable_in_query():
    data = {"prices": {"usd": 100, "eur": 90}}
    condition = JsonCondition(
        data=data,
        query="$.prices.:currency",
        return_value_test=ReturnValueTest("==", 100),
    )
    context = {":currency": "usd"}
    result, value = condition.verify(**context)
    assert result is True
    assert value == 100


def test_json_condition_from_lingo_expression():
    lingo_dict = {
        "conditionType": "json",
        "data": {"store": {"book": [{"price": 10.5}]}},
        "query": "$.store.book[0].price",
        "returnValueTest": {
            "comparator": "==",
            "value": 10.5,
        },
    }

    cls = ConditionLingo.resolve_condition_class(lingo_dict, version=1)
    assert cls == JsonCondition

    lingo_json = json.dumps(lingo_dict)
    condition = JsonCondition.from_json(lingo_json)
    assert isinstance(condition, JsonCondition)
    assert condition.to_dict() == lingo_dict


def test_json_condition_ambiguous_json_path_multiple_results():
    data = {"store": {"book": [{"price": 1}, {"price": 2}]}}
    condition = JsonCondition(
        data=data,
        query="$.store.book[*].price",
        return_value_test=ReturnValueTest("==", 1),
    )
    with pytest.raises(Exception):
        condition.verify()


def test_json_condition_invalid_jsonpath_syntax():
    """Test that invalid JSONPath syntax is caught during initialization."""
    data = {"store": {"book": [{"price": 10.5}]}}
    with pytest.raises(InvalidCondition, match="not a valid JSONPath expression"):
        JsonCondition(
            data=data,
            query="$[invalid syntax",  # Invalid JSONPath
            return_value_test=ReturnValueTest("==", 10.5),
        )


def test_json_condition_no_matches_found():
    """Test that a query with no matches raises ConditionEvaluationFailed."""
    from nucypher.policy.conditions.exceptions import ConditionEvaluationFailed

    data = {"store": {"book": [{"price": 10.5}]}}
    condition = JsonCondition(
        data=data,
        query="$.store.nonexistent",  # Path doesn't exist
        return_value_test=ReturnValueTest("==", 10.5),
    )
    with pytest.raises(ConditionEvaluationFailed, match="No matches found"):
        condition.verify()


def test_json_condition_jsonpath_error_with_context_variable():
    """Test JSONPath errors during verify when using context variables."""
    from nucypher.policy.conditions.exceptions import ConditionEvaluationFailed

    # Create a condition with a context variable in the query
    # The actual query will be resolved at verify time, so we can test runtime errors
    data = {"store": {"book": [{"price": 10.5}]}}
    condition = JsonCondition(
        data=data,
        query="$.store.:field",
        return_value_test=ReturnValueTest("==", 10.5),
    )

    # Verify with a context variable that creates an invalid path
    with pytest.raises(ConditionEvaluationFailed, match="No matches found"):
        condition.verify(**{":field": "nonexistent"})


def test_json_condition_jsonpath_parser_error_at_runtime():
    """Test that JSONPath parser errors at runtime are caught."""
    from nucypher.policy.conditions.exceptions import ConditionEvaluationFailed

    # Use context variable to inject invalid syntax at runtime (bypassing validation)
    data = {"store": {"book": [{"price": 10.5}]}}
    condition = JsonCondition(
        data=data,
        query="$.:invalid_syntax",  # Context variable will inject invalid syntax
        return_value_test=ReturnValueTest("==", 10.5),
    )

    # The context variable resolves to invalid JSONPath syntax at runtime
    with pytest.raises(ConditionEvaluationFailed, match="JSONPath error"):
        condition.verify(**{":invalid_syntax": "[invalid syntax"})
