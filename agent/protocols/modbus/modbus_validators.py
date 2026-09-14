"""Validation and normalization for Modbus action payloads."""

from .modbus_definitions import get_modbus_function_by_id


class ValidationError(Exception):
    pass


def _to_int(value, label, minimum=None, maximum=None, required=True):
    if value in (None, ""):
        if required:
            raise ValidationError(f"{label} is required")
        return None

    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{label} must be an integer") from exc

    if minimum is not None and number < minimum:
        raise ValidationError(f"{label} must be >= {minimum}")
    if maximum is not None and number > maximum:
        raise ValidationError(f"{label} must be <= {maximum}")
    return number


def _parse_csv_int_list(value, label, minimum=None, maximum=None):
    if value is None:
        raise ValidationError(f"{label} is required")

    if isinstance(value, list):
        raw_items = value
    else:
        raw_items = [item.strip() for item in str(value).split(",") if item.strip()]

    if not raw_items:
        raise ValidationError(f"{label} must contain at least one value")

    parsed = []
    for item in raw_items:
        parsed.append(_to_int(item, label, minimum=minimum, maximum=maximum, required=True))
    return parsed


def validate_modbus_action_payload(payload: dict):
    payload = payload or {}
    function_id = str(payload.get("function_id") or "").strip()

    if not function_id:
        raise ValidationError("function_id is required")

    function_def = get_modbus_function_by_id(function_id)
    if not function_def:
        raise ValidationError(f"Unsupported function_id: {function_id}")

    host = str(payload.get("host") or "").strip() or "127.0.0.1"
    port = _to_int(payload.get("port", 5020), "Port", minimum=1, maximum=65535)

    values = payload.get("values") or {}
    normalized = {
        "function_id": function_id,
        "function_code": int(function_def["code"]),
        "host": host,
        "port": port,
    }

    for field in function_def.get("fields", []):
        key = field["key"]
        label = field["label"]
        field_value = values.get(key, field.get("default"))

        if key in {"values", "write_values"}:
            normalized[key] = _parse_csv_int_list(field_value, label, minimum=0, maximum=65535)
            continue

        if key == "coils":
            parsed_coils = _parse_csv_int_list(field_value, label, minimum=0, maximum=1)
            normalized[key] = [1 if val else 0 for val in parsed_coils]
            continue

        if key == "value" and function_def["code"] == 5:
            mapped = str(field_value or "ON").strip().upper()
            if mapped not in {"ON", "OFF", "1", "0", "TRUE", "FALSE"}:
                raise ValidationError("Value must be ON or OFF for FC05")
            normalized[key] = "ON" if mapped in {"ON", "1", "TRUE"} else "OFF"
            continue

        if field.get("type") == "text":
            text_value = "" if field_value is None else str(field_value).strip()
            if field.get("required", True) and not text_value:
                raise ValidationError(f"{label} is required")
            normalized[key] = text_value
            continue

        normalized[key] = _to_int(
            field_value,
            label,
            minimum=field.get("min"),
            maximum=field.get("max"),
            required=field.get("required", True),
        )

    return function_def, normalized
