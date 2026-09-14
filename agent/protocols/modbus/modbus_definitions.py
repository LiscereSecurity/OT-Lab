"""Central source of truth for Modbus action metadata."""

from copy import deepcopy
from typing import Optional


def _field(key, label, kind="number", required=True, placeholder="", default=None, minimum=None, maximum=None, options=None, help_text=""):
    return {
        "key": key,
        "label": label,
        "type": kind,
        "required": required,
        "placeholder": placeholder,
        "default": default,
        "min": minimum,
        "max": maximum,
        "options": options or [],
        "help": help_text,
    }


MODBUS_FUNCTION_DEFINITIONS = [
    {
        "id": "fc01_read_coils",
        "code": 1,
        "code_label": "01",
        "name": "Read Coils",
        "description": "Read one or more coil bits.",
        "category": "Reading",
        "acts_on": "Coils",
        "support_note": "Common on Modbus TCP and serial.",
        "is_write": False,
        "detection_types": ["GENERIC_REQUEST", "GENERIC_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("start_addr", "Start Address", default=0, minimum=0, maximum=65535),
            _field("quantity", "Quantity", default=8, minimum=1, maximum=2000),
        ],
    },
    {
        "id": "fc02_read_discrete_inputs",
        "code": 2,
        "code_label": "02",
        "name": "Read Discrete Inputs",
        "description": "Read one or more discrete input bits.",
        "category": "Reading",
        "acts_on": "Discrete Inputs",
        "support_note": "Common in process I/O maps.",
        "is_write": False,
        "detection_types": ["GENERIC_REQUEST", "GENERIC_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("start_addr", "Start Address", default=0, minimum=0, maximum=65535),
            _field("quantity", "Quantity", default=8, minimum=1, maximum=2000),
        ],
    },
    {
        "id": "fc03_read_holding_registers",
        "code": 3,
        "code_label": "03",
        "name": "Read Holding Registers",
        "description": "Read one or more holding registers.",
        "category": "Reading",
        "acts_on": "Holding Registers",
        "support_note": "Most common Modbus function.",
        "is_write": False,
        "detection_types": ["READ_REQUEST", "READ_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("start_addr", "Start Address", default=0, minimum=0, maximum=65535),
            _field("quantity", "Quantity", default=4, minimum=1, maximum=125),
        ],
    },
    {
        "id": "fc04_read_input_registers",
        "code": 4,
        "code_label": "04",
        "name": "Read Input Registers",
        "description": "Read one or more input registers.",
        "category": "Reading",
        "acts_on": "Input Registers",
        "support_note": "Common for sensor values.",
        "is_write": False,
        "detection_types": ["READ_REQUEST", "READ_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("start_addr", "Start Address", default=0, minimum=0, maximum=65535),
            _field("quantity", "Quantity", default=4, minimum=1, maximum=125),
        ],
    },
    {
        "id": "fc05_write_single_coil",
        "code": 5,
        "code_label": "05",
        "name": "Write Single Coil",
        "description": "Write one coil ON/OFF.",
        "category": "Writing",
        "acts_on": "Coils",
        "support_note": "Standard and widely supported.",
        "is_write": True,
        "detection_types": ["WRITE_REQUEST", "WRITE_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("address", "Address", default=0, minimum=0, maximum=65535),
            _field(
                "value",
                "Value",
                kind="select",
                default="ON",
                options=[
                    {"label": "ON", "value": "ON"},
                    {"label": "OFF", "value": "OFF"},
                ],
            ),
        ],
    },
    {
        "id": "fc06_write_single_register",
        "code": 6,
        "code_label": "06",
        "name": "Write Single Register",
        "description": "Write one holding register.",
        "category": "Writing",
        "acts_on": "Holding Registers",
        "support_note": "Very common in control loops.",
        "is_write": True,
        "detection_types": ["WRITE_REQUEST", "WRITE_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("address", "Address", default=1, minimum=0, maximum=65535),
            _field("value", "Value", default=1, minimum=0, maximum=65535),
        ],
    },
    {
        "id": "fc15_write_multiple_coils",
        "code": 15,
        "code_label": "15",
        "name": "Write Multiple Coils",
        "description": "Write a sequence of coils.",
        "category": "Writing",
        "acts_on": "Coils",
        "support_note": "Used for batch actuator commands.",
        "is_write": True,
        "detection_types": ["WRITE_REQUEST", "WRITE_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("start_addr", "Start Address", default=0, minimum=0, maximum=65535),
            _field("coils", "Coils (comma list)", kind="text", placeholder="1,0,1,1", default="1,0,1,1"),
        ],
    },
    {
        "id": "fc16_write_multiple_registers",
        "code": 16,
        "code_label": "16",
        "name": "Write Multiple Registers",
        "description": "Write a sequence of holding registers.",
        "category": "Writing",
        "acts_on": "Holding Registers",
        "support_note": "Common for parameter blocks.",
        "is_write": True,
        "detection_types": ["WRITE_REQUEST", "WRITE_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("start_addr", "Start Address", default=0, minimum=0, maximum=65535),
            _field("values", "Values (comma list)", kind="text", placeholder="10,20,30", default="10,20,30"),
        ],
    },
    {
        "id": "fc07_read_exception_status",
        "code": 7,
        "code_label": "07",
        "name": "Read Exception Status",
        "description": "Read device exception status byte.",
        "category": "Diagnostics",
        "acts_on": "Diagnostics",
        "support_note": "More common on serial devices.",
        "is_write": False,
        "detection_types": ["GENERIC_REQUEST", "GENERIC_RESPONSE"],
        "fields": [_field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255)],
    },
    {
        "id": "fc08_diagnostics",
        "code": 8,
        "code_label": "08",
        "name": "Diagnostics",
        "description": "Diagnostic subfunction invocation.",
        "category": "Diagnostics",
        "acts_on": "Diagnostics",
        "support_note": "Most useful in serial environments.",
        "is_write": False,
        "detection_types": ["GENERIC_REQUEST", "GENERIC_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("subfunction", "Subfunction", default=0, minimum=0, maximum=65535),
            _field("data", "Data", default=0, minimum=0, maximum=65535, required=False),
        ],
    },
    {
        "id": "fc11_get_comm_event_counter",
        "code": 11,
        "code_label": "11",
        "name": "Get Comm Event Counter",
        "description": "Read communication event counter.",
        "category": "Diagnostics",
        "acts_on": "Diagnostics",
        "support_note": "Less frequent in Modbus TCP.",
        "is_write": False,
        "detection_types": ["GENERIC_REQUEST", "GENERIC_RESPONSE"],
        "fields": [_field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255)],
    },
    {
        "id": "fc12_get_comm_event_log",
        "code": 12,
        "code_label": "12",
        "name": "Get Comm Event Log",
        "description": "Read communication event log.",
        "category": "Diagnostics",
        "acts_on": "Diagnostics",
        "support_note": "Device dependent support.",
        "is_write": False,
        "detection_types": ["GENERIC_REQUEST", "GENERIC_RESPONSE"],
        "fields": [_field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255)],
    },
    {
        "id": "fc17_report_server_id",
        "code": 17,
        "code_label": "17",
        "name": "Report Server ID",
        "description": "Read server identification string.",
        "category": "Identification",
        "acts_on": "Identification",
        "support_note": "Typically serial-first, optional on TCP.",
        "is_write": False,
        "detection_types": ["GENERIC_REQUEST", "GENERIC_RESPONSE"],
        "fields": [_field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255)],
    },
    {
        "id": "fc20_read_file_record",
        "code": 20,
        "code_label": "20",
        "name": "Read File Record",
        "description": "Read records from file objects.",
        "category": "File",
        "acts_on": "File Records",
        "support_note": "Rare in Modbus TCP; highly device specific.",
        "is_write": False,
        "detection_types": ["GENERIC_REQUEST", "GENERIC_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("file_number", "File Number", default=1, minimum=0, maximum=65535),
            _field("record_number", "Record Number", default=0, minimum=0, maximum=65535),
            _field("record_length", "Record Length", default=1, minimum=1, maximum=120),
        ],
    },
    {
        "id": "fc21_write_file_record",
        "code": 21,
        "code_label": "21",
        "name": "Write File Record",
        "description": "Write records to file objects.",
        "category": "File",
        "acts_on": "File Records",
        "support_note": "Rare and device dependent.",
        "is_write": True,
        "detection_types": ["WRITE_REQUEST", "WRITE_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("file_number", "File Number", default=1, minimum=0, maximum=65535),
            _field("record_number", "Record Number", default=0, minimum=0, maximum=65535),
            _field("record_length", "Record Length", default=1, minimum=1, maximum=120),
            _field("values", "Values (comma list)", kind="text", default="1"),
        ],
    },
    {
        "id": "fc22_mask_write_register",
        "code": 22,
        "code_label": "22",
        "name": "Mask Write Register",
        "description": "Apply AND/OR mask to register.",
        "category": "Writing",
        "acts_on": "Holding Registers",
        "support_note": "Supported by selected devices.",
        "is_write": True,
        "detection_types": ["WRITE_REQUEST", "WRITE_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("address", "Address", default=1, minimum=0, maximum=65535),
            _field("and_mask", "AND Mask", default=65535, minimum=0, maximum=65535),
            _field("or_mask", "OR Mask", default=0, minimum=0, maximum=65535),
        ],
    },
    {
        "id": "fc23_read_write_multiple_registers",
        "code": 23,
        "code_label": "23",
        "name": "Read/Write Multiple Registers",
        "description": "Read and write registers in one request.",
        "category": "Writing",
        "acts_on": "Holding Registers",
        "support_note": "Useful for transactional updates.",
        "is_write": True,
        "detection_types": ["WRITE_REQUEST", "WRITE_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("read_start", "Read Start", default=0, minimum=0, maximum=65535),
            _field("read_quantity", "Read Quantity", default=2, minimum=1, maximum=125),
            _field("write_start", "Write Start", default=1, minimum=0, maximum=65535),
            _field("write_values", "Write Values (comma list)", kind="text", default="10,20"),
        ],
    },
    {
        "id": "fc24_read_fifo_queue",
        "code": 24,
        "code_label": "24",
        "name": "Read FIFO Queue",
        "description": "Read FIFO queue contents.",
        "category": "FIFO",
        "acts_on": "FIFO",
        "support_note": "Less common and device specific.",
        "is_write": False,
        "detection_types": ["GENERIC_REQUEST", "GENERIC_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("fifo_address", "FIFO Address", default=0, minimum=0, maximum=65535),
        ],
    },
    {
        "id": "fc43_14_read_device_identification",
        "code": 43,
        "subcode": 14,
        "code_label": "43/14",
        "name": "Read Device Identification",
        "description": "Read standard device identification objects.",
        "category": "Identification",
        "acts_on": "Identification",
        "support_note": "Common in modern devices; object support varies.",
        "is_write": False,
        "detection_types": ["GENERIC_REQUEST", "GENERIC_RESPONSE"],
        "fields": [
            _field("unit_id", "Unit/Slave ID", default=1, minimum=0, maximum=255),
            _field("mei_type", "MEI Type", default=14, minimum=0, maximum=255),
            _field("device_id_code", "Device ID Code", default=1, minimum=0, maximum=255),
            _field("object_id", "Object ID", default=0, minimum=0, maximum=255),
        ],
    },
]


def get_modbus_function_definitions():
    return deepcopy(MODBUS_FUNCTION_DEFINITIONS)


def get_modbus_function_by_id(function_id: str):
    for function in MODBUS_FUNCTION_DEFINITIONS:
        if function["id"] == function_id:
            return function
    return None


def get_modbus_function_label(function_code: int, payload: Optional[dict] = None):
    payload = payload or {}
    for function in MODBUS_FUNCTION_DEFINITIONS:
        if function["code"] != function_code:
            continue

        subcode = function.get("subcode")
        if subcode is not None:
            mei_type = payload.get("mei_type")
            if mei_type is None:
                mei_type = payload.get("subfunction")
            if int(mei_type or -1) != int(subcode):
                continue

        return function["name"]
    return f"FC{function_code}"


def get_modbus_known_function_codes():
    return {item["code"] for item in MODBUS_FUNCTION_DEFINITIONS}


def get_modbus_write_function_codes():
    return {item["code"] for item in MODBUS_FUNCTION_DEFINITIONS if item.get("is_write")}
