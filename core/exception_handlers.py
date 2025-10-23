
from rest_framework.views import exception_handler


# Helper to normalize DRF error payloads into a consistent structure
def _normalize_error(payload):
    """Coerce DRF error payload into
    {
        "detail": str | list[str] (optional),
        <field>: list[str]
    }
    At least one key (detail or field errors) will be present.
    """

    # If the payload is already a dict, make a shallow copy and clean up
    if isinstance(payload, dict):
        normalized = {}
        for key, value in payload.items():
            # DRF may return ErrorDetail objects – cast to str
            if isinstance(value, (list, tuple)):
                # Field-specific errors remain lists; we'll handle 'detail' separately later
                normalized[key] = [str(v) for v in value]
            else:
                normalized[key] = str(value)
        # Promote "non_field_errors" to "detail" if present
        if "non_field_errors" in normalized and "detail" not in normalized:
            errors = normalized.pop("non_field_errors")
            normalized["detail"] = str(errors[0])

        # Ensure 'detail' value is always a single string (never a list)
        if "detail" in normalized and isinstance(normalized["detail"], (list, tuple)):
            normalized["detail"] = str(normalized["detail"][0])
        return normalized

    # If payload is a list / tuple, treat it as detail list
    if isinstance(payload, (list, tuple)):
        errors = [str(v) for v in payload]
        return {"detail": errors[0]}

    # Fallback – simple string/number etc.
    return {"detail": str(payload)}


def trendify_exception_handler(exc, context):
    '''
    Wrap every DRF error in this custom exception handler
    '''

    response = exception_handler(exc, context)

    if response is None:
        return response
    
    normalized_error = _normalize_error(response.data)

    response.data = {
        "isSuccess": False,
        "data": None,
        "error": normalized_error,
        "message": None,
    }

    return response
