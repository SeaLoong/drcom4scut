"""Publish verified CI archives as immutable previews; retain ten public previews."""

from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
REPOSITORIES = {"SeaLoong/drcom4scut", "SeaLoong/drcom4scutGUI"}
PREVIEW_TAG = re.compile(r"preview-([1-9][0-9]*)-([1-9][0-9]*)-([0-9a-f]{8})")
SHA = re.compile(r"[0-9a-f]{40}")
notes_spec = importlib.util.spec_from_file_location("release_notes", Path(__file__).with_name("release_notes.py"))
release_notes = importlib.util.module_from_spec(notes_spec)
notes_spec.loader.exec_module(release_notes)


def run_identity(environment):
    repository = environment.get("GITHUB_REPOSITORY")
    if (repository not in REPOSITORIES
            or environment.get("GITHUB_EVENT_NAME") != "push"
            or environment.get("GITHUB_REF") != "refs/heads/master"
            or environment.get("GITHUB_SERVER_URL") != "https://github.com"):
        raise ValueError("Automatic previews require a push to the upstream master branch")
    sha = environment.get("GITHUB_SHA", "")
    numbers = [environment.get(key, "") for key in (
        "GITHUB_RUN_NUMBER", "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_ID",
    )]
    if not SHA.fullmatch(sha) or any(not re.fullmatch(r"[1-9][0-9]*", value) for value in numbers):
        raise ValueError("Invalid CI run identity")
    number, attempt, run_id = numbers
    tag = f"preview-{number}-{attempt}-{sha[:8]}"
    return repository, sha, int(number), int(attempt), run_id, tag


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect(directory):
    """Only upload archives explicitly and safely named by the checked manifest."""
    directory = Path(directory)
    checksums = directory / "SHA256SUMS"
    if checksums.is_symlink() or not checksums.is_file():
        raise ValueError("Missing regular SHA256SUMS file")
    archives = {}
    for line in checksums.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*\.(?:zip|tar\.gz))", line)
        if not match or match[2] in archives:
            raise ValueError("Invalid or duplicate checksum entry")
        path = directory / match[2]
        if path.is_symlink() or not path.is_file() or digest(path) != match[1]:
            raise ValueError(f"Archive checksum mismatch: {match[2]}")
        archives[match[2]] = path
    actual = {path.name for path in directory.iterdir() if path.name.endswith((".zip", ".tar.gz"))}
    if not archives or actual != set(archives):
        raise ValueError("Unexpected or missing release archives")
    return [archives[name] for name in sorted(archives)] + [checksums]


def marker(repository, number, attempt, sha):
    return f"<!-- drcom4scut-preview {repository} {number} {attempt} {sha} -->"


def verify_draft(release, tag, sha, assets, *, prerelease=True):
    if (release.get("draft") is not True or release.get("prerelease") is not prerelease
            or release.get("tag_name") != tag or release.get("target_commitish") != sha):
        raise ValueError("Preview draft identity or state changed")
    uploaded = release.get("assets", [])
    by_name = {asset.get("name"): asset for asset in uploaded}
    if len(uploaded) != len(by_name) or set(by_name) != {path.name for path in assets}:
        raise ValueError("Unexpected or missing remote assets")
    for path in assets:
        remote = by_name[path.name]
        if (remote.get("state") != "uploaded" or remote.get("size") != path.stat().st_size
                or remote.get("digest") != "sha256:" + digest(path)):
            raise ValueError(f"Remote upload verification failed: {path.name}")


class GitHubReleases:
    """Use the configured GitHub CLI identity without extracting its credentials."""

    def __init__(self, repository):
        if repository not in REPOSITORIES:
            raise ValueError("Unexpected preview repository")
        self.repository = repository

    def _query(self, *arguments):
        return json.loads(subprocess.check_output(["gh", *arguments], timeout=60))

    def _run(self, *arguments, timeout=60):
        subprocess.run(["gh", *arguments], check=True, timeout=timeout)

    def master_sha(self):
        reference = self._query("api", f"repos/{self.repository}/git/ref/heads/master")
        target = reference.get("object", {})
        if (reference.get("ref") != "refs/heads/master" or target.get("type") != "commit"
                or not SHA.fullmatch(target.get("sha", ""))):
            raise ValueError("Invalid master branch reference")
        return target["sha"]

    def verify_tag_target(self, tag, sha, *, required=False):
        references = self._query("api", f"repos/{self.repository}/git/matching-refs/tags/{tag}")
        if not isinstance(references, list):
            raise ValueError("Invalid tag references")
        matching = [item for item in references if item.get("ref") == "refs/tags/" + tag]
        if not matching:
            if required:
                raise ValueError("Published preview tag is missing")
            return
        if len(matching) != 1:
            raise ValueError("Duplicate tag reference")
        target = matching[0].get("object", {})
        for _ in range(5):
            if target.get("type") == "commit" and target.get("sha") == sha:
                return
            if target.get("type") != "tag" or not SHA.fullmatch(target.get("sha", "")):
                break
            target = self._query("api", f"repos/{self.repository}/git/tags/{target['sha']}").get("object", {})
        raise ValueError("Existing preview tag points at another commit; refusing overwrite")

    def create(self, tag, sha, notes):
        with tempfile.TemporaryDirectory() as directory:
            notes_file = Path(directory) / "notes.md"
            notes_file.write_text(notes, encoding="utf-8")
            self._run("release", "create", tag, "--repo", self.repository, "--target", sha,
                      "--draft", "--prerelease", "--latest=false", "--title", tag,
                      "--notes-file", str(notes_file))

    def draft(self, tag):
        url = self._query("release", "view", tag, "--repo", self.repository, "--json", "apiUrl").get("apiUrl", "")
        prefix = f"https://api.github.com/repos/{self.repository}/releases/"
        if not isinstance(url, str) or not url.startswith(prefix) or not url[len(prefix):].isdigit():
            raise ValueError("Invalid preview release endpoint")
        return self.get(int(url[len(prefix):]))

    def get(self, release_id):
        if type(release_id) is not int or release_id <= 0:
            raise ValueError("Invalid release ID")
        release = self._query("api", f"repos/{self.repository}/releases/{release_id}")
        expected = f"https://api.github.com/repos/{self.repository}/releases/{release_id}"
        if release.get("id") != release_id or release.get("url") != expected:
            raise ValueError("Remote release identity changed")
        return release

    def upload(self, tag, path):
        # No clobber: a conflicting asset leaves the draft private for inspection.
        self._run("release", "upload", tag, str(path), "--repo", self.repository, timeout=180)

    def publish(self, tag):
        self._run("release", "edit", tag, "--repo", self.repository,
                  "--draft=false", "--prerelease=true", "--latest=false")

    def list(self):
        pages = self._query("api", "--paginate", "--slurp", f"repos/{self.repository}/releases?per_page=100")
        if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
            raise ValueError("Invalid paginated releases")
        return [release for page in pages for release in page]

    def delete(self, release_id):
        if type(release_id) is not int or release_id <= 0:
            raise ValueError("Invalid release ID")
        # Delete the release only. Its immutable Git tag is deliberately retained.
        self._run("api", "--method", "DELETE", f"repos/{self.repository}/releases/{release_id}")


def current_candidate(releases, sha, number, attempt):
    if releases.master_sha() != sha:
        return False
    for release in releases.list():
        match = PREVIEW_TAG.fullmatch(release.get("tag_name", ""))
        if not match or release.get("draft") is not False or release.get("prerelease") is not True:
            continue
        target = release.get("target_commitish", "")
        if not SHA.fullmatch(target) or not target.startswith(match[3]):
            raise ValueError("Published preview identity conflicts with its tag")
        order = int(match[1]), int(match[2])
        if order == (number, attempt) and target != sha:
            raise ValueError("Published preview conflicts with this CI run")
        if order >= (number, attempt):
            return False
    return True


def published_identity(release, repository):
    """Recognize only this publisher's public preview records for retention."""
    if release.get("draft") is not False or release.get("prerelease") is not True:
        return None
    match = PREVIEW_TAG.fullmatch(release.get("tag_name", ""))
    sha = release.get("target_commitish", "")
    body = release.get("body", "")
    if (not match or not SHA.fullmatch(sha) or not sha.startswith(match[3])
            or not isinstance(body, str) or marker(repository, match[1], match[2], sha) not in body.splitlines()):
        return None
    release_id = release.get("id")
    published = release.get("published_at", "")
    if type(release_id) is not int or release_id <= 0 or not isinstance(published, str):
        raise ValueError("Invalid published preview identity")
    timestamp = datetime.fromisoformat(published.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Preview publication timestamp must include a timezone")
    return release_id, release["tag_name"], sha, published, body, timestamp


def prune_previews(releases, repository, keep=10):
    if type(keep) is not int or keep < 1:
        raise ValueError("Preview retention must be positive")
    candidates = []
    ids, tags = set(), set()
    for release in releases.list():
        identity = published_identity(release, repository)
        if identity is None:
            continue
        if identity[0] in ids or identity[1] in tags:
            raise ValueError("Duplicate preview identity")
        ids.add(identity[0])
        tags.add(identity[1])
        candidates.append(identity)
    candidates.sort(key=lambda identity: (identity[-1], identity[0]), reverse=True)
    for identity in candidates[keep:]:
        if published_identity(releases.get(identity[0]), repository) != identity:
            raise ValueError("Preview changed before cleanup; refusing deletion")
        releases.delete(identity[0])


def publish_preview(environment, directory, releases=None):
    repository, sha, number, attempt, run_id, tag = run_identity(environment)
    assets = collect(directory)
    releases = GitHubReleases(repository) if releases is None else releases
    if not current_candidate(releases, sha, number, attempt):
        print("Skipping preview: master moved or an identical/newer CI run was published")
        return False
    releases.verify_tag_target(tag, sha)
    notes = (release_notes.render(repository, sha, tag, bundles=release_notes.load_index(directory, assets), preview=True) + "\n"
             + f"[Build and tests](https://github.com/{repository}/actions/runs/{run_id})\n\n"
             f"{marker(repository, number, attempt, sha)}\n")
    releases.create(tag, sha, notes)
    for path in assets:
        releases.upload(tag, path)
    verify_draft(releases.draft(tag), tag, sha, assets)
    if not current_candidate(releases, sha, number, attempt):
        print("Keeping preview private: master moved or a newer CI run was published")
        return False
    releases.verify_tag_target(tag, sha)
    # Re-read after freshness checks so an altered draft never becomes public.
    verify_draft(releases.draft(tag), tag, sha, assets)
    releases.publish(tag)
    releases.verify_tag_target(tag, sha, required=True)
    prune_previews(releases, repository)
    print(f"Published {repository} {tag}")
    return True


if __name__ == "__main__":
    try:
        publish_preview(os.environ, ROOT / "dist")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
