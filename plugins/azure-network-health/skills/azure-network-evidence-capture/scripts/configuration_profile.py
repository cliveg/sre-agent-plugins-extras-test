"""Canonical reviewed selection and ARM scope contracts; no authentication."""

from __future__ import annotations

import math
import urllib.parse
from pathlib import Path
from typing import TypeAlias

import evidence_files as ef


Node: TypeAlias = str | dict[str, "Node"] | list["Node"]


def node(value: object) -> Node:
    if isinstance(value, str):
        if value not in ("text", "integer", "number", "bool"):
            raise ValueError("Unknown reviewed profile leaf")
        return value
    if isinstance(value, dict):
        return {key: node(entry) for key, entry in ef.obj(value).items()}
    values = ef.array(value)
    if len(values) != 1:
        raise ValueError("Reviewed array profile requires one element schema")
    return [node(values[0])]


DATA = ef.decode(ef.read_member(Path(__file__).with_name("configuration-profile.json")))
if (DATA["schemaVersion"], DATA["profileId"], DATA["profileVersion"]) != ("1.0.0", "reviewed-azure-configuration", "1.0.0"):
    raise ValueError("Unsupported reviewed configuration profile")
BASE = node(DATA["base"])
if not isinstance(BASE, dict):
    raise ValueError("Reviewed base profile must be an object")
PROPERTIES = {key: node(value) for key, value in ef.obj(DATA["properties"]).items()}
TYPES = {key: tuple(ef.text(part) for part in ef.array(value)) for key, value in ef.obj(DATA["types"]).items()}
ROOTS = tuple(ef.text(value) for value in ef.array(DATA["roots"]))
OPS = {key: (ef.text(ef.array(value)[0]), ef.text(ef.array(value)[1]),
             None if ef.array(value)[2] is None else ef.text(ef.array(value)[2]))
       for key, value in ef.obj(DATA["operations"]).items()}
CHILDREN = {key: tuple(ef.text(value) for value in ef.array(entry)) for key, entry in ef.obj(DATA["children"]).items()}
PROFILE_SHA = ef.digest({key: DATA[key] for key in ("base", "properties", "types", "roots", "operations", "children")})
MAX_PAGES = 100
MAX_JOBS = 500
MAX_READS = 100


def schema(op: str) -> dict[str, Node]:
    kind, family, suffix = OPS[op]
    properties = PROPERTIES[family]
    if not isinstance(properties, dict):
        raise ValueError("Reviewed resource properties must be an object")
    return dict(BASE) if kind == "list" and suffix is None else {**BASE, "properties": properties}


def resource_id(value: object, subscription: str, resource_type: str) -> str:
    identifier = ef.text(value)
    parts = identifier.lower().split("/")
    if (
        len(parts) < 9 or len(parts) % 2 != 1 or parts[1:3] != ["subscriptions", subscription]
        or parts[3] != "resourcegroups" or parts[5] != "providers"
        or "/".join([parts[6], *parts[7::2]]) != resource_type.lower()
        or any(part in ("", ".", "..") for part in parts[1:])
        or any(character in identifier for character in ("\\", "?", "#", "%"))
    ):
        raise ValueError("Resource identifier/type exceeds approved scope")
    return identifier


def initial_url(op: str, subscription: str, target: str | None) -> str:
    kind, family, suffix = OPS[op]
    resource_type, api = TYPES[family]
    if kind == "get":
        path = resource_id(target, subscription, resource_type)
    elif suffix:
        path = resource_id(target, subscription, resource_type.rsplit("/", 1)[0]) + "/" + suffix
    else:
        if target is not None:
            raise ValueError("Root read cannot have a parent")
        path = "/subscriptions/" + subscription + "/providers/" + resource_type
    return "https://management.azure.com" + urllib.parse.quote(path, safe="/") + "?api-version=" + api


def validate_url(value: object, op: str, subscription: str, target: str | None) -> str:
    url = ef.text(value)
    actual, base = urllib.parse.urlsplit(url), urllib.parse.urlsplit(initial_url(op, subscription, target))
    parameters = urllib.parse.parse_qsl(actual.query, keep_blank_values=True)
    if (
        actual.scheme != "https" or actual.hostname != "management.azure.com" or actual.port not in (None, 443)
        or actual.username or actual.password or actual.fragment
        or urllib.parse.unquote(actual.path).lower() != urllib.parse.unquote(base.path).lower()
        or len(parameters) != len({key for key, _ in parameters})
        or any(key not in ("api-version", "$skiptoken", "$skipToken", "$top") for key, _ in parameters)
        or dict(parameters).get("api-version") != TYPES[OPS[op][1]][1]
        or (OPS[op][0] == "get" and parameters != urllib.parse.parse_qsl(base.query))
    ):
        raise ValueError("ARM continuation exceeds approved parent/scope/API")
    if "$top" in dict(parameters) and not 1 <= int(dict(parameters)["$top"]) <= ef.MAX_ROWS:
        raise ValueError("ARM continuation row budget exceeds profile")
    return url


def same_request(left: object, right: object) -> bool:
    first, second = (urllib.parse.urlsplit(ef.text(value)) for value in (left, right))
    return (first.scheme == second.scheme and first.netloc.lower() == second.netloc.lower()
            and first.path.lower() == second.path.lower()
            and sorted(urllib.parse.parse_qsl(first.query)) == sorted(urllib.parse.parse_qsl(second.query)))


def scalar(value: object, kind: str) -> None:
    if value is None:
        return
    if kind == "text":
        ef.text(value)
    elif kind == "integer":
        ef.integer(value)
    elif kind == "bool":
        if not isinstance(value, bool):
            raise ValueError("Invalid reviewed configuration boolean")
    elif kind == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
            raise ValueError("Invalid reviewed configuration number")
    else:
        raise ValueError("Unknown reviewed scalar")


def select(value: object, shape: Node, path: str = "") -> tuple[object, list[str]]:
    if value is None:
        return None, []
    if isinstance(shape, dict):
        source = ef.obj(value)
        selected: ef.Record = {}
        omitted = [path + "/" + key for key in source if key not in shape]
        for key in source.keys() & shape.keys():
            retained, omissions = select(source[key], shape[key], path + "/" + key)
            selected[key] = retained
            omitted.extend(omissions)
        return selected, sorted(omitted)
    if isinstance(shape, list):
        values = ef.array(value)
        if len(values) > ef.MAX_ROWS:
            raise ValueError("Reviewed array row budget exceeded")
        selected = []
        omitted = []
        for position, entry in enumerate(values):
            retained, omissions = select(entry, shape[0], path + "/" + str(position))
            selected.append(retained)
            omitted.extend(omissions)
        return selected, sorted(omitted)
    scalar(value, shape)
    return value, []


def validate_retained(value: object, shape: Node) -> None:
    retained, omitted = select(value, shape)
    if omitted or retained != value:
        raise ValueError("Unreviewed fields in retained configuration")
