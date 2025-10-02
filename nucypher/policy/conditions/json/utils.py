from typing import Any, Optional

from nucypher.utilities.logging import Logger


def process_result_for_condition_eval(result: Any):
    # strings that are not already quoted will cause a problem for literal_eval
    if not isinstance(result, str):
        return result

    # check if already quoted; if not, quote it
    if not (
        (result.startswith("'") and result.endswith("'"))
        or (result.startswith('"') and result.endswith('"'))
    ):
        quote_type_to_use = '"' if "'" in result else "'"
        result = f"{quote_type_to_use}{result}{quote_type_to_use}"

    return result


def query_json_data(data: Any, query: Optional[str], **context) -> Any:
    """
    Shared utility to query JSON data with a JSONPath expression.
    Handles context variable resolution and query execution.
    """
    if not query:
        return data  # no query, return raw data

    from jsonpath_ng.exceptions import JsonPathLexerError, JsonPathParserError
    from jsonpath_ng.ext import parse

    from nucypher.policy.conditions.context import resolve_any_context_variables
    from nucypher.policy.conditions.exceptions import (
        ConditionEvaluationFailed,
        JsonRequestException,
    )

    resolved_query = resolve_any_context_variables(query, **context)
    logger = Logger(__name__)

    try:
        expression = parse(resolved_query)
        matches = expression.find(data)
        if not matches:
            message = f"No matches found for the JSONPath query: {resolved_query}"
            logger.info(message)
            raise ConditionEvaluationFailed(message)
    except (JsonPathLexerError, JsonPathParserError) as jsonpath_err:
        logger.error(f"JSONPath error occurred: {jsonpath_err}")
        raise ConditionEvaluationFailed(
            f"JSONPath error: {jsonpath_err}"
        ) from jsonpath_err

    if len(matches) > 1:
        message = (
            f"Ambiguous JSONPath query - multiple matches found for: {resolved_query}"
        )
        logger.info(message)
        raise JsonRequestException(message)

    result = matches[0].value
    return result
