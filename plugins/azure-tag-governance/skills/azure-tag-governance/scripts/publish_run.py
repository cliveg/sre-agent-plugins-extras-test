#!/usr/bin/env python3
"""Publish one verified Azure Tag Governance run with optimistic concurrency."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tag_governance as governance


TRAILER = "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"


def git(directory: Path, *arguments: str, required: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        ["git", "-C", str(directory), *arguments],
        capture_output=True,
        timeout=120,
        check=False,
    )
    if required and result.returncode:
        raise RuntimeError(
            f"Git {arguments[0]} failed with exit {result.returncode}; raw credentials/errors omitted"
        )
    return result


def repository_matches(remote: str, expected: str) -> bool:
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", expected) is None:
        return False
    uri = urllib.parse.urlsplit(remote)
    return (
        uri.scheme == "https"
        and uri.hostname == "github.com"
        and not uri.query
        and not uri.fragment
        and uri.path.rstrip("/").removesuffix(".git") == "/" + expected
    ) or remote in {"git@github.com:" + expected, "git@github.com:" + expected + ".git"}


def remote_head(repo: Path, branch: str) -> str | None:
    result = git(repo, "ls-remote", "--heads", "origin", "refs/heads/" + branch)
    lines = result.stdout.decode("utf-8").splitlines()
    if not lines:
        return None
    if len(lines) != 1:
        raise ValueError("Output branch reference is ambiguous")
    commit, reference = lines[0].split()
    if reference != "refs/heads/" + branch or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("Output branch reference is invalid")
    return commit


def validate_destination(value: str) -> str:
    parts = value.replace("\\", "/").split("/")
    if len(parts) != 4 or parts[0] != "tag-governance":
        raise ValueError("Destination must be tag-governance/<subscription>/<scope>/<run-id>")
    for index, item in enumerate(parts):
        if index and (not re.fullmatch(r"[A-Za-z0-9_.:-]+", item) or item in {".", ".."}):
            raise ValueError("Destination contains an unsafe path component")
    return "/".join(parts)


def publish(run_dir: Path, repo_root: Path, expected_repository: str, branch: str,
            expected_head: str, destination: str) -> dict[str, object]:
    run = governance.verify_run(run_dir)
    destination = validate_destination(destination)
    if destination.split("/")[-1] != run["runId"]:
        raise ValueError("Destination run ID differs from verified run")
    if re.fullmatch(r"[A-Za-z0-9._/-]+", branch) is None or ".." in branch:
        raise ValueError("Branch is invalid")
    if re.fullmatch(r"[0-9a-f]{40}", expected_head) is None:
        raise ValueError("Expected head must be a 40-character commit ID")
    repo = repo_root.resolve(strict=True)
    remote = git(repo, "config", "--get", "remote.origin.url").stdout.decode("utf-8").strip()
    if not repository_matches(remote, expected_repository):
        raise ValueError("Connected output remote differs from the approved repository")
    actual_head = remote_head(repo, branch)
    if actual_head != expected_head:
        raise RuntimeError("Output branch changed before publication; reload latest run and retry")

    original_status = git(repo, "status", "--porcelain").stdout
    original_head = git(repo, "rev-parse", "HEAD").stdout
    git(repo, "fetch", "origin", "refs/heads/" + branch)
    if git(repo, "rev-parse", "FETCH_HEAD").stdout.decode("utf-8").strip() != expected_head:
        raise RuntimeError("Fetched branch differs from the expected head")

    root = Path(tempfile.mkdtemp(prefix="tag-governance-publish-"))
    worktree = root / "worktree"
    added = False
    published = False
    try:
        git(repo, "worktree", "add", "--detach", str(worktree), expected_head)
        added = True
        target = worktree.joinpath(*destination.split("/"))
        if os.path.lexists(target):
            existing = governance.verify_run(target)
            if existing["runId"] == run["runId"]:
                raise FileExistsError("Run already exists remotely; verify the existing commit before retry")
            raise FileExistsError("Immutable destination already exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(run_dir, target)
        latest_source = run_dir.parent / "latest.json"
        latest_target = target.parent / "latest.json"
        shutil.copyfile(latest_source, latest_target)
        staged_paths = [destination, "/".join(destination.split("/")[:-1] + ["latest.json"])]
        git(worktree, "add", "--", *staged_paths)
        actual_staged = set(git(worktree, "diff", "--cached", "--name-only").stdout.decode("utf-8").splitlines())
        expected_staged = {
            destination + "/" + name for name in governance.ARTIFACTS + ("run.json",)
        } | {staged_paths[1]}
        if actual_staged != expected_staged:
            raise ValueError("Unexpected output files staged; publication stopped")
        message = f"tag-governance: {destination.split('/')[-2]} {run['runId']} ({run['status']})\n\n{TRAILER}"
        git(
            worktree,
            "-c", "user.name=Azure SRE Agent",
            "-c", "user.email=sre-agent@users.noreply.github.com",
            "commit", "-m", message,
        )
        commit = git(worktree, "rev-parse", "HEAD").stdout.decode("utf-8").strip()
        push = git(worktree, "push", "origin", "HEAD:refs/heads/" + branch, required=False)
        if push.returncode or remote_head(repo, branch) != commit:
            raise RuntimeError("Optimistic push was not confirmed; reload remote state before retry")
        published = True
        git(repo, "fetch", "origin", "refs/heads/" + branch)
        if git(repo, "rev-parse", "FETCH_HEAD").stdout.decode("utf-8").strip() != commit:
            raise RuntimeError("Published commit read-back failed")
        if git(repo, "status", "--porcelain").stdout != original_status:
            raise RuntimeError("Original connected worktree changed during publication")
        if git(repo, "rev-parse", "HEAD").stdout != original_head:
            raise RuntimeError("Original connected branch changed during publication")
        return {
            "status": "published-remote-verified",
            "repository": expected_repository,
            "branch": branch,
            "parentCommit": expected_head,
            "commit": commit,
            "runId": run["runId"],
            "destination": destination,
            "azureMutations": 0,
        }
    finally:
        if added and published and not git(worktree, "status", "--porcelain").stdout.strip():
            git(repo, "worktree", "remove", str(worktree))
        if not worktree.exists():
            root.rmdir()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = publish(
            args.run_dir, args.repository_root, args.expected_repository,
            args.branch, args.expected_head, args.destination,
        )
        governance.write_json(args.receipt, receipt)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (FileExistsError, OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
