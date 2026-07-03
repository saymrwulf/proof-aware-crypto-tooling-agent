from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_data(path: str | Path) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    return loads(text)


def dump_data(data: Any, path: str | Path) -> None:
    Path(path).write_text(dumps(data), encoding="utf-8")


def loads(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return None
    if stripped[0] in "[{":
        return json.loads(stripped)
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ModuleNotFoundError:
        return _SimpleYAML(text).parse()


def dumps(data: Any) -> str:
    try:
        import yaml  # type: ignore

        return yaml.safe_dump(data, sort_keys=False)
    except ModuleNotFoundError:
        return json.dumps(data, indent=2, sort_keys=False) + "\n"


class _SimpleYAML:
    """Small YAML subset reader for the repository examples.

    It supports indentation-based mappings, lists, strings, booleans, nulls,
    integers, and JSON-style inline arrays/objects. It is not a general YAML
    implementation; install PyYAML for broader syntax.
    """

    def __init__(self, text: str) -> None:
        self.lines = [
            line.rstrip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def parse(self) -> Any:
        if not self.lines:
            return None
        value, index = self._parse_block(0, self._indent(self.lines[0]))
        if index != len(self.lines):
            raise ValueError(f"Could not parse YAML near line {index + 1}")
        return value

    def _parse_block(self, index: int, indent: int) -> tuple[Any, int]:
        stripped = self.lines[index].lstrip()
        if stripped.startswith("-"):
            return self._parse_list(index, indent)
        return self._parse_mapping(index, indent)

    def _parse_mapping(self, index: int, indent: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        while index < len(self.lines):
            line = self.lines[index]
            current = self._indent(line)
            if current < indent:
                break
            if current > indent:
                raise ValueError(f"Unexpected indentation near line {index + 1}")
            stripped = line.lstrip()
            if stripped.startswith("-"):
                break
            if ":" not in stripped:
                raise ValueError(f"Expected key/value near line {index + 1}")
            key, raw = stripped.split(":", 1)
            key = key.strip()
            raw = raw.strip()
            if raw:
                result[key] = self._scalar(raw)
                index += 1
            else:
                index += 1
                if index >= len(self.lines) or self._indent(self.lines[index]) <= current:
                    result[key] = {}
                else:
                    result[key], index = self._parse_block(index, self._indent(self.lines[index]))
        return result, index

    def _parse_list(self, index: int, indent: int) -> tuple[list[Any], int]:
        result: list[Any] = []
        while index < len(self.lines):
            line = self.lines[index]
            current = self._indent(line)
            if current < indent:
                break
            if current != indent:
                raise ValueError(f"Unexpected list indentation near line {index + 1}")
            stripped = line.lstrip()
            if not stripped.startswith("-"):
                break
            item = stripped[1:].strip()
            index += 1
            if not item:
                if index < len(self.lines) and self._indent(self.lines[index]) > current:
                    value, index = self._parse_block(index, self._indent(self.lines[index]))
                    result.append(value)
                else:
                    result.append(None)
                continue
            if ":" in item and not item.startswith(("http://", "https://")):
                key, raw = item.split(":", 1)
                obj: dict[str, Any] = {key.strip(): self._scalar(raw.strip()) if raw.strip() else {}}
                if index < len(self.lines) and self._indent(self.lines[index]) > current:
                    more, index = self._parse_mapping(index, self._indent(self.lines[index]))
                    obj.update(more)
                result.append(obj)
            else:
                result.append(self._scalar(item))
        return result, index

    @staticmethod
    def _indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    @staticmethod
    def _scalar(raw: str) -> Any:
        if raw == "":
            return ""
        lowered = raw.lower()
        if lowered in {"null", "none", "~"}:
            return None
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if raw.startswith(("[", "{")):
            return json.loads(raw)
        if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
            return raw[1:-1]
        try:
            return int(raw)
        except ValueError:
            return raw
