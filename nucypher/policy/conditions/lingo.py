"""
 This file is part of nucypher.

 nucypher is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 nucypher is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""

import ast
import base64
import json
import operator
from typing import Any, Dict, List, Union

from marshmallow import fields, post_load

from nucypher.policy.conditions._utils import (
    CamelCaseSchema,
    _deserialize_condition_lingo,
)
from nucypher.policy.conditions.base import ReencryptionCondition
from nucypher.policy.conditions.context import is_context_variable


class Operator:
    OPERATORS = ('and', 'or')

    def __init__(self, operator: str):
        if operator not in self.OPERATORS:
            raise Exception(f'{operator} is not a valid operator')
        self.operator = operator

    def __str__(self) -> str:
        return self.operator

    def to_dict(self) -> Dict[str, str]:
        return {'operator': self.operator}

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'Operator':
        try:
            operator = data['operator']
        except KeyError:
            raise Exception(f'Invalid operator JSON')
        instance = cls(operator=operator)
        return instance

    @classmethod
    def from_json(cls, data) -> 'Operator':
        data = json.loads(data)
        instance = cls.from_dict(data)
        return instance

    def to_json(self) -> str:
        data = self.to_dict()
        data = json.dumps(data)
        return data


class ReturnValueTest:
    class InvalidExpression(ValueError):
        pass

    _COMPARATOR_FUNCTIONS = {
        "==": operator.eq,
        "!=": operator.ne,
        ">": operator.gt,
        "<": operator.lt,
        "<=": operator.le,
        ">=": operator.ge,
    }
    COMPARATORS = tuple(_COMPARATOR_FUNCTIONS)

    class ReturnValueTestSchema(CamelCaseSchema):
        comparator = fields.Str()
        value = fields.Raw(allow_none=False)  # any valid type (excludes None)

        @post_load
        def make(self, data, **kwargs):
            return ReturnValueTest(**data)

    def __init__(self, comparator: str, value):
        if comparator not in self.COMPARATORS:
            raise self.InvalidExpression(
                f'"{comparator}" is not a permitted comparator.'
            )

        if not is_context_variable(value):
            # verify that value is valid, but don't set it here so as not to change the value;
            # it will be sanitized at eval time. Need to maintain serialization/deserialization
            # consistency
            self._sanitize_value(value)

        self.comparator = comparator
        self.value = value

    def _sanitize_value(self, value):
        try:
            return ast.literal_eval(str(value))
        except Exception:
            raise self.InvalidExpression(f'"{value}" is not a permitted value.')

    def eval(self, data) -> bool:
        if is_context_variable(self.value):
            # programming error if we get here
            raise RuntimeError(
                f"'{self.value}' is an unprocessed context variable and is not valid "
                f"for condition evaluation."
            )
        left_operand = self._sanitize_value(data)
        right_operand = self._sanitize_value(self.value)
        result = self._COMPARATOR_FUNCTIONS[self.comparator](left_operand, right_operand)
        return result


class ConditionLingo:
    """
    A Collection of re-encryption conditions evaluated as a compound boolean expression.

    This is an alternate implementation of the condition expression format used in the Lit Protocol (https://github.com/LIT-Protocol);
    credit to the authors for inspiring this work. 
    """

    class Failed(Exception):
        pass

    def __init__(self, conditions: List[Union[ReencryptionCondition, Operator, Any]]):
        """
        The input list must be structured:
        condition
        operator
        condition
        ...
        """
        self._validate(lingo=conditions)
        self.conditions = conditions

    @staticmethod
    def _validate(lingo) -> None:
        if len(lingo) % 2 == 0:
            raise ValueError('conditions must be odd length, ever other element being an operator')
        for index, element in enumerate(lingo):
            if (not index % 2) and not (isinstance(element, ReencryptionCondition)):
                raise Exception(f'{index} element must be a condition; Got {type(element)}.')
            elif (index % 2) and (not isinstance(element, Operator)):
                raise Exception(f'{index} element must be an operator; Got {type(element)}.')

    @classmethod
    def from_list(cls, payload: List[Dict[str, str]]) -> 'ConditionLingo':
        conditions = [_deserialize_condition_lingo(c) for c in payload]
        instance = cls(conditions=conditions)
        return instance

    def to_list(self):  # TODO: __iter__ ?
        payload = [c.to_dict() for c in self.conditions]
        return payload

    def to_json(self) -> str:
        data = json.dumps(self.to_list())
        return data

    @classmethod
    def from_json(cls, data: str) -> 'ConditionLingo':
        data = json.loads(data)
        instance = cls.from_list(payload=data)
        return instance

    def to_base64(self) -> bytes:
        data = base64.b64encode(self.to_json().encode())
        return data

    @classmethod
    def from_base64(cls, data: bytes) -> 'ConditionLingo':
        data = base64.b64decode(data).decode()
        instance = cls.from_json(data)
        return instance

    def __bytes__(self) -> bytes:
        data = self.to_json().encode()
        return data

    def __eval(self, eval_string: str):
        # TODO: Additional protection and/or sanitation here
        result = eval(eval_string)
        return result

    def __process(self, *args, **kwargs):
        for task in self.conditions:
            if isinstance(task, ReencryptionCondition):
                condition = task
                result, value = condition.verify(*args, **kwargs)
                yield result
            elif isinstance(task, Operator):
                yield task
            else:
                raise TypeError(f"Unrecognized type {type(task)} for ConditionLingo")

    def eval(self, *args, **kwargs) -> bool:
        data = self.__process(*args, **kwargs)
        # [True, <Operator>, False] -> 'True or False'
        eval_string = ' '.join(str(e) for e in data)
        result = self.__eval(eval_string=eval_string)
        if not result:
            raise self.Failed
        return True


OR = Operator('or')
AND = Operator('and')
