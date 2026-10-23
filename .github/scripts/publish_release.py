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
    releases = ManualReleases(repository, prerelease) if releases is None else releases
    releases.verify_tag_target(tag, sha, required=True)
    notes = preview.release_notes.render(repository, sha, tag, preview=prerelease)
    releases.create(tag, sha, notes)
    for path in assets:
        releases.upload(tag, path)
    releases.verify_tag_target(tag, sha, required=True)
    preview.verify_draft(releases.draft(tag), tag, sha, assets, prerelease=prerelease)
    if draft == "false":
        releases.publish(tag)
    print(f"{'Prepared draft' if draft == 'true' else 'Published'} {repository} {tag}")


if __name__ == "__main__":
    publish_manual(os.environ, ROOT / "dist")
