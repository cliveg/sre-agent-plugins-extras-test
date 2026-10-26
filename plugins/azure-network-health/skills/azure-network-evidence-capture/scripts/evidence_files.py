"""Bounded, deterministic evidence primitives shared by capture and replay."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4


Record = dict[str, object]
MAX_MEMBER_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ROWS = 1000


def obj(value: object) -> Record:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("Expected an object with string keys")
    return value


def array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError("Expected an array")
    return value


def records(value: object) -> list[Record]:
    return [obj(entry) for entry in array(value)]


def text(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Expected a string")
    return value


def integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("Expected an integer")
    return value


def canonical_uuid(value: str) -> str:
    return str(UUID(value))


def encoded(value: object, *, compact: bool = False) -> bytes:
    return (json.dumps(
        value, sort_keys=True, indent=None if compact else 2,
        separators=(",", ":") if compact else None, allow_nan=False,
    ) + "\n").encode()


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def timestamp(value: object) -> str:
    value = text(value)
    if not value.endswith("Z"):
        raise ValueError("Evidence timestamp must be UTC Z")
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def fields(value: object, required: set[str], optional: set[str] | None = None) -> Record:
    record = obj(value)
    if not required <= set(record) or set(record) - required - (optional or set()):
        raise ValueError("Unsupported or missing evidence fields")
    return record


def unique_fields(pairs: list[tuple[str, object]]) -> Record:
    result: Record = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field in evidence")
        result[key] = value
    return result


def invalid_constant(value: str) -> object:
    raise ValueError("Nonfinite JSON number in evidence")


def decode(content: bytes) -> Record:
    return obj(json.loads(content.decode("utf-8"), object_pairs_hook=unique_fields, parse_constant=invalid_constant))


def normal_path(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or (os.name == "nt" and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise ValueError("Evidence links and reparse points are not permitted")


def read_member(path: Path, limit: int = MAX_MEMBER_BYTES) -> bytes:
    normal_path(path)
    if not path.is_file():
        raise ValueError("Evidence member must be a regular file")
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if not content or len(content) > limit:
        raise ValueError("Evidence member exceeds its byte budget or is empty")
    return content


def descriptor(name: str, content: bytes) -> Record:
    return {"name": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}


def member_name(value: object) -> str:
    name = text(value)
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*\.json", name) is None:
        raise ValueError("Unsafe or unsupported evidence member name")
    return name


def descriptors(value: object, names: set[str]) -> dict[str, Record]:
    result = {}
    for entry in records(value):
        entry = fields(entry, {"name", "bytes", "sha256"})
        name = member_name(entry["name"])
        if name not in names or name in result:
            raise ValueError("Unsafe, duplicate or unsupported evidence member")
        if not 0 < integer(entry["bytes"]) <= MAX_MEMBER_BYTES or re.fullmatch(r"[0-9a-f]{64}", text(entry["sha256"])) is None:
            raise ValueError("Invalid evidence member bytes/hash")
        result[name] = entry
    if set(result) != names:
        raise ValueError("Missing evidence members")
    return result


def read_verified_members(directory: Path, expected: dict[str, Record], base_bytes: int = 0) -> dict[str, bytes]:
    if base_bytes + sum(integer(entry["bytes"]) for entry in expected.values()) > MAX_TOTAL_BYTES:
        raise ValueError("Evidence total byte budget exceeded")
    result = {}
    for name, entry in expected.items():
        content = read_member(directory / name)
        if descriptor(name, content) != entry:
            raise ValueError("Evidence member integrity mismatch")
        result[name] = content
    return result


def immutable_file(path: Path, content: bytes) -> None:
    if os.path.lexists(path):
        normal_path(path)
        if read_member(path, max(MAX_MEMBER_BYTES, len(content))) != content:
            raise ValueError("Immutable evidence differs from original")
        return
    verified = False
    try:
        with path.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != content:
            raise OSError("Immutable evidence read-back failed")
        verified = True
    finally:
        if not verified:
            path.unlink(missing_ok=True)


def atomic_json(path: Path, value: Record) -> None:
    temporary = path.parent / ("." + uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(encoded(value))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
