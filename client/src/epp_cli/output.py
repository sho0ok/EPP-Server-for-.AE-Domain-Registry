"""
CLI Output Formatting

Handles JSON, table, and raw output formats.
"""

import json
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


def format_output(data: Any, format: str = "table", raw_xml: str = None) -> str:
    """
    Format data for output.

    Args:
        data: Data to format (dataclass, dict, list, etc.)
        format: Output format - table, json, xml
        raw_xml: Raw XML for xml format

    Returns:
        Formatted string
    """
    if format == "xml":
        if raw_xml:
            return raw_xml
        return "No XML data available"

    if format == "json":
        return format_json(data)

    # Default to table format
    return format_table(data)


def format_json(data: Any) -> str:
    """
    Format data as JSON.

    Args:
        data: Data to format

    Returns:
        JSON string
    """
    def serialize(obj):
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, (list, tuple)):
            return [serialize(item) for item in obj]
        if isinstance(obj, dict):
            return {k: serialize(v) for k, v in obj.items()}
        return obj

    return json.dumps(serialize(data), indent=2, default=str)


def format_table(data: Any) -> str:
    """
    Format data as human-readable table.

    Args:
        data: Data to format

    Returns:
        Table string
    """
    if data is None:
        return "No data"

    if is_dataclass(data):
        return format_dataclass_table(data)

    if isinstance(data, list):
        if not data:
            return "No results"
        if is_dataclass(data[0]):
            return format_list_table(data)
        return "\n".join(str(item) for item in data)

    if isinstance(data, dict):
        return format_dict_table(data)

    return str(data)


def format_dataclass_table(obj: Any) -> str:
    """
    Format dataclass as key-value table.

    Args:
        obj: Dataclass instance

    Returns:
        Table string
    """
    lines = []
    data = asdict(obj) if is_dataclass(obj) else obj

    # Calculate max key width
    max_key_width = max(len(str(k)) for k in data.keys()) if data else 0

    for key, value in data.items():
        # Skip None values and empty lists
        if value is None:
            continue
        if isinstance(value, list) and not value:
            continue

        # Format key
        key_str = key.replace("_", " ").title()
        key_padded = key_str.ljust(max_key_width + 2)

        # Format value
        value_str = format_value(value)

        lines.append(f"{key_padded}: {value_str}")

    return "\n".join(lines)


def format_dict_table(data: Dict[str, Any]) -> str:
    """
    Format dictionary as key-value table.

    Args:
        data: Dictionary

    Returns:
        Table string
    """
    if not data:
        return "No data"

    lines = []
    max_key_width = max(len(str(k)) for k in data.keys())

    for key, value in data.items():
        key_padded = str(key).ljust(max_key_width + 2)
        value_str = format_value(value)
        lines.append(f"{key_padded}: {value_str}")

    return "\n".join(lines)


def format_list_table(items: List[Any]) -> str:
    """
    Format list of dataclasses as table.

    Args:
        items: List of dataclass instances

    Returns:
        Table string
    """
    if not items:
        return "No results"

    # Get first item to determine columns
    first = items[0]
    if is_dataclass(first):
        data = asdict(first)
    elif isinstance(first, dict):
        data = first
    else:
        return "\n".join(str(item) for item in items)

    # Get column headers
    headers = list(data.keys())

    # Calculate column widths
    widths = {}
    for header in headers:
        widths[header] = len(header)

    for item in items:
        item_data = asdict(item) if is_dataclass(item) else item
        for header in headers:
            value = item_data.get(header, "")
            value_str = format_value(value, short=True)
            widths[header] = max(widths[header], len(value_str))

    # Build table
    lines = []

    # Header row
    header_parts = []
    for header in headers:
        header_str = header.replace("_", " ").title()
        header_parts.append(header_str.ljust(widths[header]))
    lines.append("  ".join(header_parts))

    # Separator
    separator_parts = ["-" * widths[h] for h in headers]
    lines.append("  ".join(separator_parts))

    # Data rows
    for item in items:
        item_data = asdict(item) if is_dataclass(item) else item
        row_parts = []
        for header in headers:
            value = item_data.get(header, "")
            value_str = format_value(value, short=True)
            row_parts.append(value_str.ljust(widths[header]))
        lines.append("  ".join(row_parts))

    return "\n".join(lines)


def format_value(value: Any, short: bool = False) -> str:
    """
    Format a single value for display.

    Args:
        value: Value to format
        short: Whether to use short format

    Returns:
        Formatted string
    """
    if value is None:
        return ""

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, datetime):
        if short:
            return value.strftime("%Y-%m-%d")
        return value.strftime("%Y-%m-%d %H:%M:%S")

    if isinstance(value, list):
        if not value:
            return ""
        if short:
            if len(value) > 2:
                return f"{value[0]}, ... ({len(value)} total)"
            return ", ".join(str(v) for v in value)
        return ", ".join(str(v) for v in value)

    if is_dataclass(value):
        # For nested dataclasses, show summary
        data = asdict(value)
        # Try to find a name/id field
        for key in ["name", "id", "type"]:
            if key in data and data[key]:
                return str(data[key])
        return str(data)

    if isinstance(value, dict):
        if short:
            return f"({len(value)} items)"
        parts = [f"{k}={v}" for k, v in value.items()]
        return ", ".join(parts)

    return str(value)


def print_success(message: str) -> None:
    """Print success message."""
    print(f"SUCCESS: {message}")


def print_error(message: str) -> None:
    """Print error message to stderr."""
    print(f"ERROR: {message}", file=sys.stderr)


def print_warning(message: str) -> None:
    """Print warning message to stderr."""
    print(f"WARNING: {message}", file=sys.stderr)


def print_info(message: str) -> None:
    """Print info message."""
    print(f"INFO: {message}")


class OutputFormatter:
    """
    Context manager for formatted output.
    """

    def __init__(self, format: str = "table", quiet: bool = False):
        """
        Initialize formatter.

        Args:
            format: Output format (table, json, xml)
            quiet: Suppress non-essential output
        """
        self.format = format
        self.quiet = quiet

    def output(self, data: Any, raw_xml: str = None) -> None:
        """
        Output formatted data.

        Args:
            data: Data to output
            raw_xml: Raw XML for xml format
        """
        formatted = format_output(data, self.format, raw_xml)
        print(formatted)

    def success(self, message: str) -> None:
        """Print success message."""
        if not self.quiet:
            print_success(message)

    def error(self, message: str) -> None:
        """Print error message."""
        print_error(message)

    def info(self, message: str) -> None:
        """Print info message."""
        if not self.quiet:
            print_info(message)
