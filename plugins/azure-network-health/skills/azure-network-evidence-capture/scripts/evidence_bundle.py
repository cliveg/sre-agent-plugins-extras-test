"""Self-contained, bounded source packaging shared by offline evidence views."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Callable, Literal

import evidence_files as ef
import network_capture as capture


Kind = Literal["timeline", "comparison", "restriction", "review"]
Renderer = Callable[[Path, str, ef.Record], dict[str, bytes]]
SourceLoader = Callable[[Path], tuple[str, dict[str, bytes]]]
VERSION = "1.0.0"
MANIFEST = "manifest.json"
PROCESSORS = {
    "timeline": "offline-evidence-timeline", "comparison": "offline-configuration-comparison",
    "restriction": "offline-source-restriction-assessment",
    "review": "reference-led-network-assessment",
}
RESTRICTION_VIEWS = {"observed-network.json", "assessment.json", "network-assessment.md", "network-evidence.md"}


def _format(kind: Kind, version: str) -> None:
    if (version != VERSION and (kind != "timeline" or version != "1.1.0")
            and (kind != "review" or version != "1.0.1")):
        raise ValueError("Unsupported derived bundle/processor version")


def _name(value: object, kind: Kind, version: str = VERSION) -> str:
    name = ef.text(value)
    if kind in ("restriction", "review") and name in RESTRICTION_VIEWS:
        return name
    if name in (kind + ".json", kind + ".md"):
        return name
    if kind == "timeline" and version == "1.1.0" and re.fullmatch(
        r"timeline-[a-z]+(?:-[a-z]+)*-p[0-9]{4}\.(?:json|md)", name,
    ):
        return name
    parts = name.split("/")
    if kind == "review":
        if (len(parts) < 3 or parts[0] != "sources" or ef.canonical_uuid(parts[1]) != parts[1]
                or any(re.fullmatch(r"[a-z0-9][a-z0-9-]*", part) is None for part in parts[2:-1])
                or re.fullmatch(r"[a-z0-9][a-z0-9-]*\.(?:json|md)", parts[-1]) is None):
            raise ValueError("Unsupported reference-review source member path")
        return name
    if (len(parts) != 3 or parts[0] != "sources" or ef.canonical_uuid(parts[1]) != parts[1]
            or ef.member_name(parts[2]) != parts[2]):
        raise ValueError("Unsupported derived evidence member path")
    return name


def _limit(name: str) -> int:
    return ef.MAX_MANIFEST_BYTES if name.endswith("/" + MANIFEST) or name == MANIFEST else ef.MAX_MEMBER_BYTES


def _files(root: Path) -> set[str]:
    result = set()
    directories = set()
    for path in root.rglob("*"):
        ef.normal_path(path)
        name = path.relative_to(root).as_posix()
        if path.is_file():
            result.add(name)
        elif path.is_dir():
            directories.add(name)
        else:
            raise ValueError("Derived evidence contains an unsupported filesystem entry")
    expected = {parent.as_posix() for name in result for parent in Path(name).parents if parent != Path(".")}
    if directories != expected:
        raise ValueError("Derived evidence contains unexpected directories")
    return result


def _view_names(views: dict[str, bytes], kind: Kind, version: str) -> None:
    required = RESTRICTION_VIEWS if kind in ("restriction", "review") else {kind + ".json", kind + ".md"}
    if not required <= set(views) or (not (kind == "timeline" and version == "1.1.0") and set(views) != required):
        raise ValueError("Unexpected derived view membership")
    if any("/" in name or _name(name, kind, version) != name for name in views):
        raise ValueError("Unsafe derived view membership")


def verify(directory: Path, kind: Kind, render: Renderer, *, version: str = VERSION) -> ef.Record:
    _format(kind, version)
    root = capture.checked_root(directory)
    content = ef.read_member(root / MANIFEST, ef.MAX_MANIFEST_BYTES)
    fields = {"bundleVersion", kind + "Id", "processorId", "processorVersion", "processedAtUtc", "members"}
    if kind in ("comparison", "review"):
        fields.add("inputs")
    manifest = ef.fields(ef.decode(content), fields)
    if (manifest["bundleVersion"], manifest["processorId"], manifest["processorVersion"]) != (
        version, PROCESSORS[kind], version,
    ):
        raise ValueError("Unsupported derived bundle/processor version")
    identifier = ef.text(manifest[kind + "Id"])
    if ef.canonical_uuid(identifier) != identifier:
        raise ValueError("Noncanonical derived evidence identity")
    ef.timestamp(manifest["processedAtUtc"])
    expected: dict[str, ef.Record] = {}
    total = len(content)
    for entry in ef.records(manifest["members"]):
        ef.fields(entry, {"name", "bytes", "sha256"})
        name = _name(entry["name"], kind, version)
        if name in expected or not 0 < ef.integer(entry["bytes"]) <= _limit(name):
            raise ValueError("Duplicate or oversized derived evidence member")
        if re.fullmatch(r"[0-9a-f]{64}", ef.text(entry["sha256"])) is None:
            raise ValueError("Invalid derived evidence member hash")
        expected[name] = entry
        total += ef.integer(entry["bytes"])
    if total > ef.MAX_TOTAL_BYTES or _files(root) != set(expected) | {MANIFEST}:
        raise ValueError("Derived evidence membership/total byte budget differs")
    for name, entry in expected.items():
        if ef.descriptor(name, ef.read_member(root / name, _limit(name))) != entry:
            raise ValueError("Derived evidence member integrity mismatch")
    views = render(root, identifier, ef.obj(manifest["inputs"]) if kind in ("comparison", "review") else {})
    _view_names(views, kind, version)
    if set(views) != {name for name in expected if not name.startswith("sources/")}:
        raise ValueError("Unexpected derived view membership")
    if any(ef.read_member(root / name) != value for name, value in views.items()):
        raise ValueError("Derived views differ from verified source evidence")
    return manifest


def build(capsules: list[Path], identifier: str, output_root: Path, kind: Kind,
          render: Renderer, inputs: ef.Record | None = None, *, version: str = VERSION,
          source_loader: SourceLoader | None = None) -> Path:
    _format(kind, version)
    if not 1 <= len(capsules) <= 20:
        raise ValueError("Derived evidence requires between 1 and 20 input capsules")
    identifier = ef.canonical_uuid(identifier)
    root = capture.checked_root(output_root)
    if any(root.resolve().is_relative_to(source.resolve(strict=True)) for source in capsules):
        raise ValueError("Derived output must be outside every immutable source capsule")
    parent = root / ("runs" if kind in ("restriction", "review") else kind + "s")
    parent.mkdir(exist_ok=True)
    ef.normal_path(parent)
    destination = parent / identifier
    if os.path.lexists(destination):
        raise FileExistsError("Derived output already exists; immutable evidence is not overwritten")
    with tempfile.TemporaryDirectory(prefix="." + kind + "-build-", dir=parent) as temporary:
        stage = Path(temporary)
        seen = set()
        total = 0
        for source in capsules:
            if source_loader is None:
                manifest, _, manifest_bytes = capture.verified(source)
                capsule_id = ef.text(manifest["capsuleId"])
                names = {ef.text(entry["name"]) for entry in ef.records(manifest["members"])}
                expected = ef.descriptors(manifest["members"], names)
                payloads = ef.read_verified_members(source, expected, len(manifest_bytes)) | {MANIFEST: manifest_bytes}
            else:
                capsule_id, payloads = source_loader(source)
                if ef.canonical_uuid(capsule_id) != capsule_id:
                    raise ValueError("Noncanonical derived input identity")
                for name in payloads:
                    _name("sources/" + capsule_id + "/" + name, kind, version)
            if capsule_id in seen:
                raise ValueError("Duplicate source capsule identity")
            seen.add(capsule_id)
            total += sum(len(value) for value in payloads.values())
            if total > ef.MAX_TOTAL_BYTES:
                raise ValueError("Derived input byte budget exceeded")
            target = stage / "sources" / capsule_id
            target.mkdir(parents=True)
            for name, value in payloads.items():
                member = target / name
                member.parent.mkdir(parents=True, exist_ok=True)
                ef.normal_path(member.parent)
                ef.immutable_file(member, value)
        views = render(stage, identifier, inputs or {})
        _view_names(views, kind, version)
        for name, value in views.items():
            if not 0 < len(value) <= ef.MAX_MEMBER_BYTES:
                raise ValueError("Derived view byte budget exceeded")
            ef.immutable_file(stage / name, value)
        members = [ef.descriptor(name, ef.read_member(stage / name, _limit(name))) for name in sorted(_files(stage))]
        manifest = {
            "bundleVersion": version, kind + "Id": identifier, "processorId": PROCESSORS[kind],
            "processorVersion": version, "processedAtUtc": ef.utc_now(), "members": members,
        }
        if kind in ("comparison", "review"):
            manifest["inputs"] = inputs or {}
        content = ef.encoded(manifest)
        if len(content) > ef.MAX_MANIFEST_BYTES or len(content) + sum(ef.integer(entry["bytes"]) for entry in members) > ef.MAX_TOTAL_BYTES:
            raise ValueError("Derived manifest/output byte budget exceeded")
        ef.immutable_file(stage / MANIFEST, content)
        verify(stage, kind, render, version=version)
        destination.mkdir()
        for name in sorted(_files(stage) - {MANIFEST}):
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            ef.immutable_file(target, ef.read_member(stage / name, _limit(name)))
        ef.immutable_file(destination / MANIFEST, content)
    verify(destination, kind, render, version=version)
    return destination
