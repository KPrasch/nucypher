import json
from typing import Any, Optional, Tuple

from marshmallow import fields, post_load, validate

from nucypher.policy.conditions.base import Condition
from nucypher.policy.conditions.context import resolve_any_context_variables
from nucypher.policy.conditions.exceptions import InvalidCondition
from nucypher.policy.conditions.json.base import JSONPathField
from nucypher.policy.conditions.json.utils import (
    process_result_for_condition_eval,
    query_json_data,
)
from nucypher.policy.conditions.lingo import AnyField, ConditionType, ReturnValueTest


def _parse_json_data(data: Any) -> Any:
    """
    Parse JSON data if it's a string, otherwise return as-is.
    """
    if not isinstance(data, str):
        return data

    try:
        return json.loads(data)
    except (json.JSONDecodeError, ValueError) as e:
        raise InvalidCondition(f"Invalid JSON string: {e}") from e


class JsonCondition(Condition):
    """
    A JSON condition evaluates data that is directly provided as JSON.
    The data can be a dict, list, primitive value, or a JSON string.
    An optional JSONPath query can be applied to extract a specific value.
    """

    CONDITION_TYPE = ConditionType.JSON.value

    class Schema(Condition.Schema):
        condition_type = fields.Str(
            validate=validate.Equal(ConditionType.JSON.value), required=True
        )
        data = AnyField(required=True)
        query = JSONPathField(required=False, allow_none=True)
        return_value_test = fields.Nested(ReturnValueTest.Schema(), required=True)

        @post_load
        def make(self, data, **kwargs):
            return JsonCondition(**data)

    def __init__(
        self,
        data: Any,
        return_value_test: ReturnValueTest,
        query: Optional[str] = None,
        condition_type: Optional[str] = ConditionType.JSON.value,
        name: Optional[str] = None,
    ):
        # Parse JSON string if needed
        self.data = _parse_json_data(data)
        self.query = query
        self.return_value_test = return_value_test

        super().__init__(condition_type=condition_type, name=name)

    def verify(self, **context) -> Tuple[bool, Any]:
        """
        Verifies the JSON condition by executing the query and evaluating the result.
        """
        # Resolve context variables in data if needed
        resolved_data = resolve_any_context_variables(self.data, **context)

        # Apply JSONPath query
        result = query_json_data(resolved_data, self.query, **context)

        # Process result for evaluation (handles string quoting)
        result_for_eval = process_result_for_condition_eval(result)

        # Evaluate against return value test
        resolved_return_value_test = self.return_value_test.with_resolved_context(
            **context
        )
        eval_result = resolved_return_value_test.eval(result_for_eval)

        return eval_result, result
