"""Publish verified evidence bytes to an explicitly approved connected repository."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path
from typing import Literal

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_files as ef
import network_capture as capture


TRAILER = "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
ArtifactKind = Literal["capsule", "timeline", "comparison", "restriction", "review"]
COLLECTIONS = {"capsule": ("captures", "network-evidence"), "timeline": ("timelines", "network-timeline"),
               "comparison": ("comparisons", "network-comparison"), "restriction": ("runs", "network-restriction"),
               "review": ("runs", "network-review")}


def git(directory: Path, *arguments: str, required: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(["git", "-c", "core.longpaths=true", "-C", str(directory), *arguments],
                            capture_output=True, timeout=120, check=False)
    if required and result.returncode:
        raise RuntimeError("Git " + arguments[0] + " failed with exit " + str(result.returncode) + "; raw credentials/errors omitted")
    return result


def repository_matches(remote: str, expected: str) -> bool:
    uri = urllib.parse.urlsplit(remote)
    return (
        uri.scheme == "https" and uri.hostname == "github.com" and not uri.query and not uri.fragment
        and uri.path.rstrip("/").removesuffix(".git") == "/" + expected
    ) or remote in ("git@github.com:" + expected, "git@github.com:" + expected + ".git")


def artifact_paths(capsule_id: str, names: set[str], artifact_kind: ArtifactKind = "capsule") -> dict[str, str]:
    collection = COLLECTIONS[artifact_kind][0]
    return {name: "network-health/" + collection + "/" + capsule_id + "/" + name for name in sorted(names)}


def remote_commit(repo: Path, branch: str) -> str | None:
    result = git(repo, "ls-remote", "--heads", "origin", "refs/heads/" + branch)
    lines = result.stdout.decode().splitlines()
    if not lines:
        return None
    if len(lines) != 1:
        raise ValueError("Output branch reference is ambiguous")
    identifier, reference = lines[0].split()
    if reference != "refs/heads/" + branch or re.fullmatch(r"[0-9a-f]{40}", identifier) is None:
        raise ValueError("Invalid output branch reference")
    return identifier


def readback(repo: Path, branch: str, commit: str, expected: dict[str, ef.Record]) -> None:
    if remote_commit(repo, branch) != commit:
        raise ValueError("Remote branch no longer matches publication receipt")
    git(repo, "fetch", "origin", "refs/heads/" + branch)
    if git(repo, "rev-parse", "FETCH_HEAD").stdout.decode().strip() != commit:
        raise ValueError("Fetched output commit differs from receipt")
    for path, entry in expected.items():
        blob = git(repo, "show", commit + ":" + path).stdout
        if len(blob) != entry["bytes"] or hashlib.sha256(blob).hexdigest() != entry["sha256"]:
            raise ValueError("Remote committed bytes differ from original capsule")


def publish(directory: Path, repo_root: Path, expected_repository: str, *,
            private_destination_reviewed: bool = False, artifact_kind: ArtifactKind = "capsule") -> ef.Record:
    if not private_destination_reviewed:
        raise ValueError("Private destination review is required; Git cloning does not prove visibility")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", expected_repository) is None:
        raise ValueError("Expected repository must be owner/name")
    if artifact_kind not in COLLECTIONS:
        raise ValueError("Unsupported publication artifact kind")
    repo = repo_root.resolve(strict=True)
    ef.normal_path(repo_root)
    if not repo.is_dir():
        raise ValueError("Connected repository root is unavailable")
    remote = git(repo, "config", "--get", "remote.origin.url").stdout.decode().strip()
    if not repository_matches(remote, expected_repository):
        raise ValueError("Connected output remote differs from the approved repository")
    if artifact_kind == "capsule":
        manifest = capture.verify(directory)
        identifier = ef.canonical_uuid(ef.text(manifest["capsuleId"]))
        identity: ef.Record = {"capsuleId": identifier}
    else:
        if artifact_kind == "timeline":
            import network_timeline
            manifest = network_timeline.verify(directory)
        elif artifact_kind == "comparison":
            import network_comparison
            manifest = network_comparison.verify(directory)
        elif artifact_kind == "restriction":
            import network_restriction
            manifest = network_restriction.verify(directory)
        else:
            import network_reference
            manifest = network_reference.verify(directory)
        identifier = ef.canonical_uuid(ef.text(manifest[artifact_kind + "Id"]))
        identity = {artifact_kind + "Id": identifier, "artifactKind": artifact_kind}
    members = {ef.text(entry["name"]) for entry in ef.records(manifest["members"])} | {capture.MANIFEST}
    paths = artifact_paths(identifier, members, artifact_kind)
    originals = {name: ef.read_member(directory / name, ef.MAX_MANIFEST_BYTES if name == capture.MANIFEST else ef.MAX_MEMBER_BYTES)
                 for name in members}
    descriptors = {ef.text(entry["name"]): entry for entry in ef.records(manifest["members"])}
    if ef.decode(originals[capture.MANIFEST]) != manifest or any(
        ef.descriptor(name, originals[name]) != entry for name, entry in descriptors.items()
    ):
        raise ValueError("Verified evidence changed before publication")
    expected = {paths[name]: ef.descriptor(name, content) for name, content in originals.items()}
    branch = COLLECTIONS[artifact_kind][1] + "/" + identifier
    existing = remote_commit(repo, branch)
    if existing is not None:
        readback(repo, branch, existing, expected)
        return {"publicationVersion": "1.0.0", "repository": expected_repository, "branch": branch, "commit": existing,
                **identity, "status": "existing-remote-bytes-verified", "remoteReferenceConfirmed": True,
                "artifacts": [{"path": path, **entry} for path, entry in sorted(expected.items())],
                "azureReads": 0, "azureMutations": 0, "privateDestinationAssurance": "operatorReviewed"}
    status_before = git(repo, "status", "--porcelain").stdout
    head_before = git(repo, "rev-parse", "HEAD").stdout
    git(repo, "fetch", "origin", "main")
    parent = git(repo, "rev-parse", "FETCH_HEAD").stdout.decode().strip()
    root = Path(tempfile.mkdtemp(prefix="network-evidence-publish-"))
    worktree = root / "worktree"
    added = False
    confirmed = False
    try:
        git(repo, "worktree", "add", "-b", branch, str(worktree), parent)
        added = True
        collection = COLLECTIONS[artifact_kind][0]
        for ancestor in (worktree / "network-health", worktree / "network-health" / collection):
            if os.path.lexists(ancestor):
                ef.normal_path(ancestor)
        destination = worktree / "network-health" / collection / identifier
        if os.path.lexists(destination):
            raise FileExistsError("Capsule output path already exists")
        destination.mkdir(parents=True)
        for name in sorted(members):
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            ef.normal_path(target.parent)
            ef.immutable_file(target, originals[name])
        # A single owned path avoids the Windows process argument limit.
        git(worktree, "add", "--", destination.relative_to(worktree).as_posix())
        if set(git(worktree, "diff", "--cached", "--name-only").stdout.decode().splitlines()) != set(paths.values()):
            raise ValueError("Unexpected output files staged; publication stopped")
        label = ("configuration evidence" if artifact_kind == "capsule" else
                 "source restriction assessment" if artifact_kind == "restriction" else "evidence " + artifact_kind)
        message = "network-health: " + label + " " + identifier + "\n\n" + TRAILER
        git(worktree, "-c", "user.name=Azure SRE Agent", "-c", "user.email=sre-agent@users.noreply.github.com",
            "commit", "-m", message)
        commit = git(worktree, "rev-parse", "HEAD").stdout.decode().strip()
        for path, entry in expected.items():
            blob = git(worktree, "show", commit + ":" + path).stdout
            if blob != originals[ef.text(entry["name"])]:
                raise ValueError("Local commit bytes differ from verified capsule")
        push = git(worktree, "push", "origin", "HEAD:refs/heads/" + branch, required=False)
        if remote_commit(repo, branch) != commit:
            raise RuntimeError("Push outcome unconfirmed; inspect remote branch before any retry")
        confirmed = True
        readback(repo, branch, commit, expected)
        if git(repo, "status", "--porcelain").stdout != status_before or git(repo, "rev-parse", "HEAD").stdout != head_before:
            raise ValueError("Original connected/WARA worktree changed during publication")
        return {
            "publicationVersion": "1.0.0", "repository": expected_repository, "branch": branch, "commit": commit,
            "parentCommit": parent, **identity, "status": "published-remote-bytes-verified",
            "pushExitCode": push.returncode, "remoteReferenceConfirmed": True, "originalWorktreePreserved": True,
            "artifacts": [{"path": path, **entry} for path, entry in sorted(expected.items())],
            "azureReads": 0, "azureMutations": 0, "privateDestinationAssurance": "operatorReviewed",
        }
    finally:
        if added and confirmed and not git(worktree, "status", "--porcelain").stdout.strip():
            git(repo, "worktree", "remove", str(worktree))
        if not worktree.exists():
            root.rmdir()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--capsule", type=Path)
    source.add_argument("--timeline", type=Path)
    source.add_argument("--comparison", type=Path)
    source.add_argument("--restriction", type=Path)
    source.add_argument("--review", type=Path)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--private-destination-reviewed", action="store_true")
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    try:
        directory = args.capsule or args.timeline or args.comparison or args.restriction or args.review
        kind: ArtifactKind
        if args.timeline is not None:
            kind = "timeline"
        elif args.comparison is not None:
            kind = "comparison"
        elif args.restriction is not None:
            kind = "restriction"
        elif args.review is not None:
            kind = "review"
        else:
            kind = "capsule"
        if os.path.lexists(args.receipt) or args.receipt.resolve().is_relative_to(directory.resolve()):
            raise ValueError("Publication receipt must be new and outside the immutable evidence")
        result = publish(directory, args.repository_root, args.expected_repository,
                         private_destination_reviewed=args.private_destination_reviewed, artifact_kind=kind)
        content = ef.encoded(result)
        ef.immutable_file(args.receipt, content)
    except (ValueError, OSError, RuntimeError) as error:
        parser.exit(2, "Evidence publication failed: " + str(error) + "\n")
    summary = {key: value for key, value in result.items() if key != "artifacts"}
    summary.update({
        "artifactCount": len(ef.array(result["artifacts"])), "receipt": str(args.receipt),
        "receiptSha256": hashlib.sha256(content).hexdigest(),
        "manifestSha256": hashlib.sha256(ef.read_member(directory / capture.MANIFEST, ef.MAX_MANIFEST_BYTES)).hexdigest(),
    })
    print(ef.encoded(summary).decode().strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
