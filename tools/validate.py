#!/usr/bin/env python3
"""Validate marketplace plugins and companion YAML assets."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    raise ValueError(message)


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"Invalid JSON {path.relative_to(ROOT)}: {exc}")


def load_yaml(path: Path) -> object:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"Invalid YAML {path.relative_to(ROOT)}: {exc}")


def skill_frontmatter(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not match:
        fail(f"Missing YAML frontmatter: {path.relative_to(ROOT)}")
    data = yaml.safe_load(match.group(1))
    if not isinstance(data, dict):
        fail(f"Invalid skill frontmatter: {path.relative_to(ROOT)}")
    return data


def validate_plugin(plugin_dir: Path) -> str:
    manifest_path = plugin_dir / "plugin.json"
    if not manifest_path.is_file():
        fail(f"Missing plugin.json in {plugin_dir.relative_to(ROOT)}")
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        fail(f"Plugin manifest must be an object: {manifest_path}")

    plugin_id = str(manifest.get("id", ""))
    if plugin_id != plugin_dir.name:
        fail(f"Plugin id '{plugin_id}' does not match folder '{plugin_dir.name}'")
    if not manifest.get("version"):
        fail(f"Plugin {plugin_id} has no version")

    skills = manifest.get("skills")
    if not isinstance(skills, list) or not skills:
        fail(f"Plugin {plugin_id} has no skills")
    for skill in skills:
        if not isinstance(skill, dict):
            fail(f"Plugin {plugin_id} has an invalid skill entry")
        path = plugin_dir / str(skill.get("path", ""))
        if not path.is_file():
            fail(f"Plugin {plugin_id} references missing skill {path}")
        frontmatter = skill_frontmatter(path)
        if frontmatter.get("name") != skill.get("name"):
            fail(
                f"Skill name mismatch in {path.relative_to(ROOT)}: "
                f"{frontmatter.get('name')} != {skill.get('name')}"
            )

    for path in plugin_dir.rglob("*.yaml"):
        load_yaml(path)
    for path in plugin_dir.rglob("*.yml"):
        load_yaml(path)
    for path in plugin_dir.rglob("*.json"):
        load_json(path)

    return plugin_id


def main() -> int:
    plugins_dir = ROOT / "plugins"
    plugin_ids = {
        validate_plugin(path)
        for path in sorted(plugins_dir.iterdir())
        if path.is_dir()
    }

    for marketplace_path in (
        ROOT / "marketplace.json",
        ROOT / ".github" / "plugin" / "marketplace.json",
    ):
        marketplace = load_json(marketplace_path)
        if not isinstance(marketplace, dict):
            fail(f"Marketplace must be an object: {marketplace_path}")
        entries = marketplace.get("plugins")
        if not isinstance(entries, list):
            fail(f"Marketplace has no plugin list: {marketplace_path}")
        listed = {str(entry.get("name", "")) for entry in entries}
        if listed != plugin_ids:
            fail(
                f"{marketplace_path.relative_to(ROOT)} plugin set "
                f"{sorted(listed)} != {sorted(plugin_ids)}"
            )
        for entry in entries:
            source = ROOT / str(entry.get("source", ""))
            if not source.is_dir():
                fail(
                    f"Missing marketplace source "
                    f"{entry.get('source')} in {marketplace_path}"
                )

    runner = (
        ROOT
        / "plugins"
        / "vm-migration-preassessment"
        / "extras"
        / "github"
        / "vm-preassessment.yml"
    )
    runner_text = runner.read_text(encoding="utf-8")
    for required in (
        "github.event.repository.private",
        "vm-preassessment-reusable.yml",
        "AZURE_CLIENT_ID",
        "AZURE_TENANT_ID",
        "assessment-summary.json",
        "No migration actions were performed.",
    ):
        if required not in runner_text:
            fail(f"VM pre-assessment runner is missing '{required}'")

    reusable = (
        ROOT.parent / "AzVMTools" / ".github" / "workflows"
        / "vm-preassessment-reusable.yml"
    )
    if reusable.exists():
        load_yaml(reusable)

    print(f"PASS: validated {len(plugin_ids)} plugins: {', '.join(sorted(plugin_ids))}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
