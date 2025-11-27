"""
Tests for optional returnValueTest feature.

When a condition is inside a ConditionVariable (sequential conditions),
returnValueTest can be omitted. In this case:
- The condition returns (True, extracted_value) if extraction succeeds
- Operations on ConditionVariable still work
- Standalone conditions (outside ConditionVariable) still require returnValueTest
"""

import json

import pytest

from nucypher.policy.conditions.exceptions import InvalidConditionLingo
from nucypher.policy.conditions.json.json import JsonCondition
from nucypher.policy.conditions.lingo import (
    ConditionLingo,
    ConditionVariable,
    ReturnValueTest,
    SequentialCondition,
    VariableOperation,
)
from nucypher.policy.conditions.utils import ConditionProviderManager, _eth_to_wei
from nucypher.policy.conditions.var import ContextVariableCondition


class TestJsonConditionOptionalReturnValueTest:
    """Tests for JsonCondition with optional returnValueTest."""

    def test_json_condition_without_rvt_direct_construction(self):
        """JsonCondition can be created without returnValueTest via direct Python construction."""
        json_cond = JsonCondition(
            data=":input",
            query="$.value",
            # No returnValueTest
        )
        assert json_cond.return_value_test is None

    def test_json_condition_without_rvt_verify_returns_true(self):
        """JsonCondition.verify() returns (True, value) when returnValueTest is None."""
        json_cond = JsonCondition(
            data=":input",
            query="$.value",
        )

        context = {":input": json.dumps({"value": 42})}
        result, value = json_cond.verify(**context)

        assert result is True
        assert value == 42

    def test_json_condition_without_rvt_verify_with_nested_query(self):
        """JsonCondition without RVT works with complex JSONPath queries."""
        json_cond = JsonCondition(
            data=":input",
            query="$.data.options[?(@.name=='amount')].value",
        )

        context = {
            ":input": json.dumps(
                {
                    "data": {
                        "options": [
                            {"name": "amount", "value": "0.001"},
                            {"name": "recipient", "value": "0xABC"},
                        ]
                    }
                }
            )
        }
        result, value = json_cond.verify(**context)

        assert result is True
        assert value == "0.001"

    def test_json_condition_with_rvt_still_works(self):
        """JsonCondition with returnValueTest still works as before."""
        json_cond = JsonCondition(
            data=":input",
            query="$.value",
            return_value_test=ReturnValueTest(comparator="==", value=42),
        )

        # Should pass when value matches
        context = {":input": json.dumps({"value": 42})}
        result, value = json_cond.verify(**context)
        assert result is True
        assert value == 42

        # Should fail when value doesn't match
        context = {":input": json.dumps({"value": 100})}
        result, value = json_cond.verify(**context)
        assert result is False
        assert value == 100

    def test_standalone_json_condition_from_dict_requires_rvt(self):
        """JsonCondition.from_dict() requires returnValueTest when standalone."""
        with pytest.raises(InvalidConditionLingo, match="returnValueTest"):
            JsonCondition.from_dict(
                {
                    "conditionType": "json",
                    "data": ":input",
                    "query": "$.value",
                    # No returnValueTest - should fail
                }
            )

    def test_json_condition_serialization_without_rvt(self):
        """JsonCondition without RVT serializes correctly (no returnValueTest key)."""
        json_cond = JsonCondition(
            data=":input",
            query="$.value",
        )

        serialized = json_cond.to_dict()
        assert "returnValueTest" not in serialized
        assert serialized["conditionType"] == "json"
        assert serialized["data"] == ":input"
        assert serialized["query"] == "$.value"


class TestContextVariableConditionOptionalReturnValueTest:
    """Tests for ContextVariableCondition with optional returnValueTest."""

    def test_context_var_condition_without_rvt_direct_construction(self):
        """ContextVariableCondition can be created without returnValueTest."""
        ctx_cond = ContextVariableCondition(
            context_variable=":myVar",
            # No returnValueTest
        )
        assert ctx_cond.return_value_test is None

    def test_context_var_condition_without_rvt_verify_returns_true(self):
        """ContextVariableCondition.verify() returns (True, value) when returnValueTest is None."""
        ctx_cond = ContextVariableCondition(
            context_variable=":myVar",
        )

        context = {":myVar": "test_value"}
        result, value = ctx_cond.verify(
            providers=ConditionProviderManager({}), **context
        )

        assert result is True
        assert value == "test_value"

    def test_context_var_condition_without_rvt_verify_with_complex_value(self):
        """ContextVariableCondition without RVT works with complex values."""
        ctx_cond = ContextVariableCondition(
            context_variable=":data",
        )

        complex_value = {"nested": {"key": [1, 2, 3]}}
        context = {":data": complex_value}
        result, value = ctx_cond.verify(
            providers=ConditionProviderManager({}), **context
        )

        assert result is True
        assert value == complex_value

    def test_context_var_condition_with_rvt_still_works(self):
        """ContextVariableCondition with returnValueTest still works as before."""
        ctx_cond = ContextVariableCondition(
            context_variable=":myVar",
            return_value_test=ReturnValueTest(comparator="==", value=42),
        )

        # Should pass when value matches
        context = {":myVar": 42}
        result, value = ctx_cond.verify(
            providers=ConditionProviderManager({}), **context
        )
        assert result is True

        # Should fail when value doesn't match
        context = {":myVar": 100}
        result, value = ctx_cond.verify(
            providers=ConditionProviderManager({}), **context
        )
        assert result is False

    def test_standalone_context_var_condition_from_dict_requires_rvt(self):
        """ContextVariableCondition.from_dict() requires returnValueTest when standalone."""
        with pytest.raises(InvalidConditionLingo, match="returnValueTest"):
            ContextVariableCondition.from_dict(
                {
                    "conditionType": "context-variable",
                    "contextVariable": ":myVar",
                    # No returnValueTest - should fail
                }
            )


class TestSequentialConditionWithOptionalReturnValueTest:
    """Tests for SequentialCondition with conditions that have optional returnValueTest."""

    def test_sequential_with_first_condition_without_rvt(self):
        """SequentialCondition works when first condition has no returnValueTest."""
        # First condition: extraction without RVT
        extract_cond = JsonCondition(
            data=":input",
            query="$.value",
        )

        # Second condition: validate the extracted value
        validate_cond = ContextVariableCondition(
            context_variable=":extracted",
            return_value_test=ReturnValueTest(comparator="==", value=42),
        )

        seq_cond = SequentialCondition(
            condition_variables=[
                ConditionVariable(var_name="extracted", condition=extract_cond),
                ConditionVariable(var_name="validated", condition=validate_cond),
            ]
        )

        context = {":input": json.dumps({"value": 42})}
        result, values = seq_cond.verify(
            providers=ConditionProviderManager({}), **context
        )

        assert result is True
        assert values[0] == 42  # Extracted value
        assert values[1] == 42  # Validated value

    def test_sequential_with_all_conditions_without_rvt_except_last(self):
        """SequentialCondition with all but last condition having no returnValueTest."""
        # First condition: extraction without RVT
        cond1 = JsonCondition(data=":input", query="$.a")

        # Second condition: passthrough without RVT
        cond2 = ContextVariableCondition(context_variable=":val1")

        # Third condition: final validation with RVT
        cond3 = ContextVariableCondition(
            context_variable=":val2",
            return_value_test=ReturnValueTest(comparator="==", value=100),
        )

        seq_cond = SequentialCondition(
            condition_variables=[
                ConditionVariable(var_name="val1", condition=cond1),
                ConditionVariable(var_name="val2", condition=cond2),
                ConditionVariable(var_name="final", condition=cond3),
            ]
        )

        context = {":input": json.dumps({"a": 100})}
        result, values = seq_cond.verify(
            providers=ConditionProviderManager({}), **context
        )

        assert result is True
        assert values == [100, 100, 100]

    def test_sequential_with_operations_on_condition_without_rvt(self):
        """ConditionVariable.operations work with condition that has no returnValueTest."""
        # Extraction without RVT
        extract_cond = JsonCondition(
            data=":input",
            query="$.amount",
        )

        # Validate the transformed value
        validate_cond = ContextVariableCondition(
            context_variable=":amount",
            return_value_test=ReturnValueTest(
                comparator="==",
                value=_eth_to_wei(0.001),
            ),
        )

        seq_cond = SequentialCondition(
            condition_variables=[
                ConditionVariable(
                    var_name="amount",
                    condition=extract_cond,
                    operations=[
                        VariableOperation(operation="ethToWei"),
                    ],
                ),
                ConditionVariable(var_name="validated", condition=validate_cond),
            ]
        )

        context = {":input": json.dumps({"amount": "0.001"})}
        result, values = seq_cond.verify(
            providers=ConditionProviderManager({}), **context
        )

        assert result is True
        # values[0] is the raw extracted value before operations
        assert values[0] == "0.001"
        # values[1] is the transformed value from the second condition
        # (which read :amount after ethToWei operation was applied)
        assert values[1] == _eth_to_wei(0.001)

    def test_sequential_with_multiple_operations_on_condition_without_rvt(self):
        """Multiple operations work with condition that has no returnValueTest."""
        extract_cond = JsonCondition(
            data=":input",
            query="$.value",
        )

        validate_cond = ContextVariableCondition(
            context_variable=":processed",
            return_value_test=ReturnValueTest(comparator="==", value=30),
        )

        seq_cond = SequentialCondition(
            condition_variables=[
                ConditionVariable(
                    var_name="processed",
                    condition=extract_cond,
                    operations=[
                        VariableOperation(operation="*=", value=2),  # 10 * 2 = 20
                        VariableOperation(operation="+=", value=10),  # 20 + 10 = 30
                    ],
                ),
                ConditionVariable(var_name="validated", condition=validate_cond),
            ]
        )

        context = {":input": json.dumps({"value": 10})}
        result, values = seq_cond.verify(
            providers=ConditionProviderManager({}), **context
        )

        assert result is True
        # values[0] is the raw extracted value (10), operations are applied to context
        assert values[0] == 10
        # values[1] is the transformed value from the second condition (30)
        assert values[1] == 30

    def test_sequential_mixed_conditions_with_and_without_rvt(self):
        """Sequential with mixed conditions - some with RVT, some without."""
        data = {"amount": "100", "recipient": "0xABC", "timestamp": 1234567890}

        # Extraction without RVT
        extract_amount = JsonCondition(data=":data", query="$.amount")

        # Extraction with RVT (validates recipient is not zero)
        extract_recipient = JsonCondition(
            data=":data",
            query="$.recipient",
            return_value_test=ReturnValueTest(comparator="!=", value="0x0"),
        )

        # Passthrough without RVT
        passthrough = ContextVariableCondition(context_variable=":recipient")

        # Final validation with RVT
        final_check = ContextVariableCondition(
            context_variable=":passthrough",
            return_value_test=ReturnValueTest(comparator="==", value="0xABC"),
        )

        seq_cond = SequentialCondition(
            condition_variables=[
                ConditionVariable(var_name="amount", condition=extract_amount),
                ConditionVariable(var_name="recipient", condition=extract_recipient),
                ConditionVariable(var_name="passthrough", condition=passthrough),
                ConditionVariable(var_name="final", condition=final_check),
            ]
        )

        context = {":data": json.dumps(data)}
        result, values = seq_cond.verify(
            providers=ConditionProviderManager({}), **context
        )

        assert result is True
        assert values[0] == "100"  # Extracted without RVT
        assert values[1] == "0xABC"  # Extracted with RVT
        assert values[2] == "0xABC"  # Passthrough without RVT
        assert values[3] == "0xABC"  # Final validation with RVT


class TestConditionLingoWithOptionalReturnValueTest:
    """Tests for ConditionLingo deserialization with optional returnValueTest."""

    def test_lingo_with_sequential_condition_without_rvt(self):
        """ConditionLingo deserializes sequential condition with nested condition without RVT."""
        condition_dict = {
            "version": "1.0.0",
            "condition": {
                "conditionType": "sequential",
                "conditionVariables": [
                    {
                        "varName": "extracted",
                        "condition": {
                            "conditionType": "json",
                            "data": ":input",
                            "query": "$.value",
                            # No returnValueTest
                        },
                    },
                    {
                        "varName": "validated",
                        "condition": {
                            "conditionType": "context-variable",
                            "contextVariable": ":extracted",
                            "returnValueTest": {
                                "comparator": "==",
                                "value": 42,
                            },
                        },
                    },
                ],
            },
        }

        lingo = ConditionLingo.from_dict(condition_dict)

        # Verify the condition was created correctly
        seq_cond = lingo.condition
        assert isinstance(seq_cond, SequentialCondition)
        assert len(seq_cond.condition_variables) == 2

        # First condition should have no return_value_test
        first_cond = seq_cond.condition_variables[0].condition
        assert isinstance(first_cond, JsonCondition)
        assert first_cond.return_value_test is None

        # Second condition should have return_value_test
        second_cond = seq_cond.condition_variables[1].condition
        assert isinstance(second_cond, ContextVariableCondition)
        assert second_cond.return_value_test is not None

    def test_lingo_serialization_roundtrip(self):
        """ConditionLingo serializes and deserializes correctly with optional RVT."""
        condition_dict = {
            "version": "1.0.0",
            "condition": {
                "conditionType": "sequential",
                "conditionVariables": [
                    {
                        "varName": "extracted",
                        "condition": {
                            "conditionType": "json",
                            "data": ":input",
                            "query": "$.value",
                            # No returnValueTest
                        },
                    },
                    {
                        "varName": "validated",
                        "condition": {
                            "conditionType": "context-variable",
                            "contextVariable": ":extracted",
                            "returnValueTest": {
                                "comparator": "==",
                                "value": 42,
                            },
                        },
                    },
                ],
            },
        }

        # Deserialize
        lingo = ConditionLingo.from_dict(condition_dict)

        # Serialize back
        serialized = lingo.to_dict()

        # Check that the first condition has no returnValueTest
        first_cond = serialized["condition"]["conditionVariables"][0]["condition"]
        assert "returnValueTest" not in first_cond

        # Check that the second condition still has returnValueTest
        second_cond = serialized["condition"]["conditionVariables"][1]["condition"]
        assert "returnValueTest" in second_cond
        assert second_cond["returnValueTest"]["comparator"] == "=="
        assert second_cond["returnValueTest"]["value"] == 42

    def test_lingo_standalone_condition_requires_rvt(self):
        """ConditionLingo.from_dict() fails for standalone condition without RVT."""
        # JsonCondition
        with pytest.raises(InvalidConditionLingo, match="returnValueTest"):
            ConditionLingo.from_dict(
                {
                    "version": "1.0.0",
                    "condition": {
                        "conditionType": "json",
                        "data": ":input",
                        "query": "$.value",
                    },
                }
            )

        # ContextVariableCondition
        with pytest.raises(InvalidConditionLingo, match="returnValueTest"):
            ConditionLingo.from_dict(
                {
                    "version": "1.0.0",
                    "condition": {
                        "conditionType": "context-variable",
                        "contextVariable": ":myVar",
                    },
                }
            )

    def test_lingo_with_operations_and_without_rvt(self):
        """ConditionLingo works with ConditionVariable operations and no RVT on condition."""
        condition_dict = {
            "version": "1.0.0",
            "condition": {
                "conditionType": "sequential",
                "conditionVariables": [
                    {
                        "varName": "amount",
                        "condition": {
                            "conditionType": "json",
                            "data": ":input",
                            "query": "$.amount",
                            # No returnValueTest
                        },
                        "operations": [
                            {"operation": "ethToWei"},
                        ],
                    },
                    {
                        "varName": "validated",
                        "condition": {
                            "conditionType": "context-variable",
                            "contextVariable": ":amount",
                            "returnValueTest": {
                                "comparator": ">",
                                "value": 0,
                            },
                        },
                    },
                ],
            },
        }

        lingo = ConditionLingo.from_dict(condition_dict)

        # Verify evaluation works
        context = {":input": json.dumps({"amount": "0.001"})}
        result = lingo.eval(providers=ConditionProviderManager({}), **context)
        assert result is True


class TestBackwardsCompatibility:
    """Tests ensuring backwards compatibility with existing conditions."""

    def test_existing_conditions_with_rvt_still_work(self):
        """Existing conditions with returnValueTest continue to work."""
        # JsonCondition with RVT
        json_cond = JsonCondition(
            data=":input",
            query="$.value",
            return_value_test=ReturnValueTest(comparator="==", value=42),
        )

        context = {":input": json.dumps({"value": 42})}
        result, value = json_cond.verify(**context)
        assert result is True
        assert value == 42

        # ContextVariableCondition with RVT
        ctx_cond = ContextVariableCondition(
            context_variable=":myVar",
            return_value_test=ReturnValueTest(comparator="==", value=100),
        )

        context = {":myVar": 100}
        result, value = ctx_cond.verify(
            providers=ConditionProviderManager({}), **context
        )
        assert result is True
        assert value == 100

    def test_existing_sequential_conditions_still_work(self):
        """Existing sequential conditions with all RVTs continue to work."""
        cond1 = JsonCondition(
            data=":input",
            query="$.a",
            return_value_test=ReturnValueTest(comparator=">", value=0),
        )

        cond2 = ContextVariableCondition(
            context_variable=":val",
            return_value_test=ReturnValueTest(comparator="==", value=100),
        )

        seq_cond = SequentialCondition(
            condition_variables=[
                ConditionVariable(var_name="val", condition=cond1),
                ConditionVariable(var_name="final", condition=cond2),
            ]
        )

        context = {":input": json.dumps({"a": 100})}
        result, values = seq_cond.verify(
            providers=ConditionProviderManager({}), **context
        )

        assert result is True
        assert values == [100, 100]

    def test_existing_lingo_format_still_works(self):
        """Existing Lingo format with all RVTs continues to work."""
        condition_dict = {
            "version": "1.0.0",
            "condition": {
                "conditionType": "sequential",
                "conditionVariables": [
                    {
                        "varName": "extracted",
                        "condition": {
                            "conditionType": "json",
                            "data": ":input",
                            "query": "$.value",
                            "returnValueTest": {
                                "comparator": ">",
                                "value": 0,
                            },
                        },
                    },
                    {
                        "varName": "validated",
                        "condition": {
                            "conditionType": "context-variable",
                            "contextVariable": ":extracted",
                            "returnValueTest": {
                                "comparator": "==",
                                "value": 42,
                            },
                        },
                    },
                ],
            },
        }

        lingo = ConditionLingo.from_dict(condition_dict)
        context = {":input": json.dumps({"value": 42})}
        result = lingo.eval(providers=ConditionProviderManager({}), **context)
        assert result is True
