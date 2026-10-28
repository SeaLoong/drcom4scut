"""Upload manual releases privately, verify every asset, then optionally publish."""
import importlib.util
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("preview_publisher", Path(__file__).with_name("publish_preview.py"))
preview = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preview)


class ManualReleases(preview.GitHubReleases):
    def __init__(self, repository, prerelease):
        super().__init__(repository)
        self.prerelease = prerelease

    def existing(self, tag):
        matches = [release for release in self.list() if release.get("tag_name") == tag]
        if len(matches) > 1:
            raise ValueError("Duplicate manual release tag")
        return self.get(matches[0].get("id")) if matches else None

    def create(self, tag, sha, notes):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            notes_file = Path(directory) / "notes.md"
            notes_file.write_text(notes, encoding="utf-8")
            flags = ["--prerelease"] if self.prerelease else []
            self._run("release", "create", tag, "--repo", self.repository, "--target", sha,
                      "--verify-tag", "--draft", "--latest=false", "--title", tag,
                      "--notes-file", str(notes_file), *flags)

    def publish(self, tag):
        self._run("release", "edit", tag, "--repo", self.repository, "--draft=false",
                  "--prerelease=" + str(self.prerelease).lower(),
                  "--latest=" + str(not self.prerelease).lower())


def pending_uploads(release, repository, tag, sha, assets, prerelease):
    """Resume only a private, exact-identity draft containing verified assets."""
    release_id = release.get("id")
    if (type(release_id) is not int or release_id <= 0
            or release.get("url") != f"https://api.github.com/repos/{repository}/releases/{release_id}"):
        raise ValueError("Existing manual release belongs to another repository or has an invalid identity")
    uploaded = release.get("assets")
    if not isinstance(uploaded, list) or any(not isinstance(asset, dict) for asset in uploaded):
        raise ValueError("Existing draft has invalid remote assets")
    names = [asset.get("name") for asset in uploaded]
    expected = {path.name for path in assets}
    if (any(not isinstance(name, str) for name in names) or len(set(names)) != len(names)
            or not set(names) <= expected):
        raise ValueError("Existing draft contains unexpected or duplicate assets; refusing changes")
    if any(asset.get("state") != "uploaded" for asset in uploaded):
        raise ValueError("Existing draft contains an unfinished or unknown upload state; refusing resume")
    present = [path for path in assets if path.name in names]
    # This rejects published releases, another commit/tag, incomplete uploads,
    # and any size or digest mismatch. Assets are never clobbered or deleted.
    preview.verify_draft(release, tag, sha, present, prerelease=prerelease)
    return [path for path in assets if path.name not in names]


def publish_manual(environment, directory, releases=None):
    repository = environment.get("GITHUB_REPOSITORY")
    sha = environment.get("GITHUB_SHA", "")
    tag = environment.get("RELEASE_TAG", "")
    draft = environment.get("CREATE_DRAFT")
    if (repository not in preview.REPOSITORIES
            or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or environment.get("GITHUB_SERVER_URL") != "https://github.com"
            or not preview.SHA.fullmatch(sha)
            or not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", tag)
            or draft not in ("true", "false")):
        raise ValueError("Manual releases require a validated upstream workflow dispatch")
    assets = preview.collect(directory)
    prerelease = "-" in tag
    bundles = preview.release_notes.load_index(directory, assets)
    sample = bundles[preview.release_notes.RUNTIMES[0]]
    version = sample["gui_version" if repository.endswith("GUI") else "core_version"]
    if tag != "v" + version:
        raise ValueError("Manual release tag must match the validated source version")
    notes = preview.release_notes.render(repository, sha, tag, bundles=bundles, preview=prerelease)
    releases = ManualReleases(repository, prerelease) if releases is None else releases
    releases.verify_tag_target(tag, sha, required=True)
    existing = releases.existing(tag)
    if existing is None:
        releases.create(tag, sha, notes)
        pending = assets
    else:
        pending = pending_uploads(existing, repository, tag, sha, assets, prerelease)
    for path in pending:
        if existing is not None:
            # A reviewer may publish or edit the retained draft while a failed
            # run is being retried. Recheck before each resumed mutation.
            current = pending_uploads(releases.draft(tag), repository, tag, sha, assets, prerelease)
            if path not in current:
                continue
        releases.upload(tag, path)
    releases.verify_tag_target(tag, sha, required=True)
    preview.verify_draft(releases.draft(tag), tag, sha, assets, prerelease=prerelease)
    if draft == "false":
        releases.publish(tag)
    print(f"{'Prepared draft' if draft == 'true' else 'Published'} {repository} {tag}")


if __name__ == "__main__":
    publish_manual(os.environ, ROOT / "dist")
