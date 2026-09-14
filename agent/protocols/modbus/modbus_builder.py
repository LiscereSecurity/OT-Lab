"""Build Modbus/TCP requests from normalized action payloads."""

from typing import Optional


def _u16(value: int) -> bytes:
    return int(value).to_bytes(2, "big", signed=False)


def _pack_coils(values: list[int]) -> bytes:
    byte_count = (len(values) + 7) // 8
    out = [0] * byte_count
    for index, bit in enumerate(values):
        if bit:
            out[index // 8] |= 1 << (index % 8)
    return bytes(out)


def _build_pdu(function_def: dict, values: dict) -> bytes:
    code = int(function_def["code"])

    if code in {1, 2, 3, 4}:
        return bytes([code]) + _u16(values["start_addr"]) + _u16(values["quantity"])

    if code == 5:
        coil = 0xFF00 if values["value"] == "ON" else 0x0000
        return bytes([code]) + _u16(values["address"]) + _u16(coil)

    if code == 6:
        return bytes([code]) + _u16(values["address"]) + _u16(values["value"])

    if code == 7:
        return bytes([code])

    if code == 8:
        data = values.get("data", 0) or 0
        return bytes([code]) + _u16(values["subfunction"]) + _u16(data)

    if code in {11, 12, 17}:
        return bytes([code])

    if code == 15:
        coils = values["coils"]
        packed = _pack_coils(coils)
        return (
            bytes([code])
            + _u16(values["start_addr"])
            + _u16(len(coils))
            + bytes([len(packed)])
            + packed
        )

    if code == 16:
        registers = values["values"]
        payload = b"".join(_u16(item) for item in registers)
        return (
            bytes([code])
            + _u16(values["start_addr"])
            + _u16(len(registers))
            + bytes([len(payload)])
            + payload
        )

    if code == 20:
        sub_request = b"\x06" + _u16(values["file_number"]) + _u16(values["record_number"]) + _u16(values["record_length"])
        return bytes([code, len(sub_request)]) + sub_request

    if code == 21:
        registers = values["values"]
        record_length = values["record_length"]
        if len(registers) < record_length:
            registers = registers + ([0] * (record_length - len(registers)))
        registers = registers[:record_length]
        data = b"".join(_u16(item) for item in registers)
        sub_request = (
            b"\x06"
            + _u16(values["file_number"])
            + _u16(values["record_number"])
            + _u16(record_length)
            + data
        )
        return bytes([code, len(sub_request)]) + sub_request

    if code == 22:
        return bytes([code]) + _u16(values["address"]) + _u16(values["and_mask"]) + _u16(values["or_mask"])

    if code == 23:
        write_values = values["write_values"]
        payload = b"".join(_u16(item) for item in write_values)
        return (
            bytes([code])
            + _u16(values["read_start"])
            + _u16(values["read_quantity"])
            + _u16(values["write_start"])
            + _u16(len(write_values))
            + bytes([len(payload)])
            + payload
        )

    if code == 24:
        return bytes([code]) + _u16(values["fifo_address"])

    if code == 43:
        mei_type = values.get("mei_type", 14)
        return bytes([code, mei_type, values["device_id_code"], values["object_id"]])

    raise ValueError(f"Unsupported function code: {code}")


def build_modbus_tcp_request(function_def: dict, values: dict, transaction_id: Optional[int] = None):
    tx_id = int(transaction_id or 1) & 0xFFFF
    unit_id = int(values.get("unit_id", 1)) & 0xFF

    pdu = _build_pdu(function_def, values)
    mbap = _u16(tx_id) + b"\x00\x00" + _u16(len(pdu) + 1) + bytes([unit_id])
    adu = mbap + pdu

    return {
        "transaction_id": tx_id,
        "unit_id": unit_id,
        "function_code": int(function_def["code"]),
        "request_bytes": adu,
        "request_hex": adu.hex(" ").upper(),
        "pdu_hex": pdu.hex(" ").upper(),
    }
