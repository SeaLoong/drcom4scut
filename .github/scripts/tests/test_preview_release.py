"""Exercise preview publication and retention without a live GitHub account."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parent / "publish_preview.py"
if not SCRIPT.is_file():
    SCRIPT = SCRIPT.parent.parent / "publish_preview.py"
spec = importlib.util.spec_from_file_location("publish_preview", SCRIPT)
preview = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preview)

REPOSITORY = "SeaLoong/drcom4scut"
SHA = "a" * 40
ENVIRONMENT = {
    "GITHUB_REPOSITORY": REPOSITORY,
    "GITHUB_SHA": SHA,
    "GITHUB_RUN_NUMBER": "42",
    "GITHUB_RUN_ATTEMPT": "2",
    "GITHUB_RUN_ID": "1234",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_EVENT_NAME": "push",
    "GITHUB_REF": "refs/heads/master",
}


def published(number, release_id=None, **changes):
    release_id = number if release_id is None else release_id
    release = {
        "id": release_id,
        "tag_name": f"preview-{number}-1-{SHA[:8]}",
        "target_commitish": SHA,
        "draft": False,
        "prerelease": True,
        "published_at": f"2026-10-{number:02d}T00:00:00Z",
        "body": preview.marker(REPOSITORY, number, 1, SHA),
    }
    release.update(changes)
    return release


class FakeReleases:
    def __init__(self):
        self.events = []
        self.records = []
        self.master = SHA
        self.current = None
        self.upload_error = False
        self.corrupt_upload = False
        self.after_upload = None
        self.changed_record = None
        self.tag_target = None

    def master_sha(self):
        self.events.append("master")
        return self.master

    def list(self):
        self.events.append("list")
        return copy.deepcopy(self.records)

    def verify_tag_target(self, tag, sha, *, required=False):
        self.events.append("tag")
        if required and self.tag_target is None:
            raise ValueError("Published preview tag is missing")
        if self.tag_target not in (None, sha):
            raise ValueError("Existing preview tag points at another commit")

    def create(self, tag, sha, notes):
        self.events.append("create")
        self.current = {
            "id": 100,
            "tag_name": tag,
            "target_commitish": sha,
            "draft": True,
            "prerelease": True,
            "body": notes,
            "assets": [],
        }
        self.records.append(self.current)

    def upload(self, tag, path):
        self.events.append("upload:" + path.name)
        if self.upload_error:
            raise subprocess.CalledProcessError(1, ["gh", "release", "upload"])
        self.current["assets"].append({
            "name": path.name,
            "size": path.stat().st_size,
            "digest": "sha256:" + ("0" * 64 if self.corrupt_upload else preview.digest(path)),
            "state": "uploaded",
        })
        if self.after_upload:
            self.after_upload(self)

    def draft(self, tag):
        self.events.append("draft")
        return copy.deepcopy(self.current)

    def publish(self, tag):
        self.events.append("publish")
        if self.tag_target is None:
            self.tag_target = self.current["target_commitish"]
        self.current["draft"] = False
        self.current["published_at"] = "2026-10-22T00:00:00Z"

    def get(self, release_id):
        self.events.append("get:" + str(release_id))
        record = copy.deepcopy(next(item for item in self.records if item["id"] == release_id))
        if self.changed_record == release_id:
            record["draft"] = True
        return record

    def delete(self, release_id):
        self.events.append("delete:" + str(release_id))
        self.records = [item for item in self.records if item["id"] != release_id]


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.dist = Path(self.temporary.name)
        self.archive = self.dist / "drcom4scut-0.4.1-win-x64.zip"
        self.archive.write_bytes(b"checked build archive")
        self.sums = self.dist / "SHA256SUMS"
        self.sums.write_text(f"{preview.digest(self.archive)}  {self.archive.name}\n")
        self.releases = FakeReleases()

    def run_preview(self, **changes):
        environment = dict(ENVIRONMENT, **changes)
        return preview.publish_preview(environment, self.dist, self.releases)

    def test_verified_draft_is_uploaded_then_published_without_changing_version(self):
        self.assertTrue(self.run_preview())
        release = self.releases.current
        self.assertEqual(release["tag_name"], "preview-42-2-aaaaaaaa")
        self.assertEqual(release["target_commitish"], SHA)
        self.assertTrue(release["prerelease"])
        self.assertFalse(release["draft"])
        self.assertEqual({item["name"] for item in release["assets"]}, {self.archive.name, "SHA256SUMS"})
        events = self.releases.events
        self.assertLess(events.index("create"), events.index("upload:" + self.archive.name))
        self.assertLess(events.index("upload:SHA256SUMS"), events.index("draft"))
        self.assertLess(events.index("draft"), events.index("publish"))
        self.assertEqual(events.count("master"), 2)
        self.assertEqual(events.count("tag"), 3)

    def test_fork_pull_request_other_branch_and_manual_ci_never_publish(self):
        for changes in (
            {"GITHUB_REPOSITORY": "someone/drcom4scut"},
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_EVENT_NAME": "workflow_dispatch"},
            {"GITHUB_REF": "refs/heads/feature"},
            {"GITHUB_SERVER_URL": "https://untrusted.invalid"},
            {"GITHUB_RUN_ATTEMPT": "0"},
            {"GITHUB_SHA": "master"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.run_preview(**changes)
        self.assertEqual(self.releases.events, [])

    def test_manifest_rejects_corruption_duplicate_names_paths_and_extra_archives(self):
        original = self.sums.read_text()
        for contents in (
            "", original + original,
            f"{'0' * 64}  {self.archive.name}\n",
            f"{preview.digest(self.archive)}  ../{self.archive.name}\n",
        ):
            with self.subTest(contents=contents), self.assertRaises(ValueError):
                self.sums.write_text(contents)
                preview.collect(self.dist)
        self.sums.write_text(original)
        (self.dist / "unexpected.zip").write_bytes(b"unverified")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            preview.collect(self.dist)

    def test_local_archive_and_checksum_symlinks_are_not_uploaded(self):
        real_archive = self.dist / "original"
        self.archive.rename(real_archive)
        try:
            self.archive.symlink_to(real_archive)
        except OSError as error:
            self.skipTest(f"Symlinks unavailable: {error}")
        with self.assertRaises(ValueError):
            self.run_preview()
        self.assertEqual(self.releases.events, [])

    def test_bad_remote_digest_or_upload_failure_keeps_draft_private(self):
        for attribute, error in (("corrupt_upload", ValueError), ("upload_error", subprocess.CalledProcessError)):
            with self.subTest(attribute=attribute):
                self.releases = FakeReleases()
                setattr(self.releases, attribute, True)
                with self.assertRaises(error):
                    self.run_preview()
                self.assertTrue(self.releases.current["draft"])
                self.assertNotIn("publish", self.releases.events)

    def test_changed_remote_asset_set_or_draft_identity_never_becomes_public(self):
        for mutate in (
            lambda api: api.current.update(target_commitish="b" * 40),
            lambda api: api.current["assets"].append({"name": "unexpected.zip"}),
        ):
            with self.subTest(mutate=mutate):
                self.releases = FakeReleases()
                self.releases.after_upload = mutate
                with self.assertRaises(ValueError):
                    self.run_preview()
                self.assertNotIn("publish", self.releases.events)

    def test_old_run_is_skipped_before_creation_and_after_upload(self):
        self.releases.master = "b" * 40
        self.assertFalse(self.run_preview())
        self.assertNotIn("create", self.releases.events)
        self.releases = FakeReleases()
        self.releases.after_upload = lambda api: setattr(api, "master", "b" * 40)
        self.assertFalse(self.run_preview())
        self.assertTrue(self.releases.current["draft"])
        self.assertNotIn("publish", self.releases.events)

    def test_newer_run_and_newer_attempt_prevent_late_publication(self):
        for release in (published(43), published(42, tag_name="preview-42-3-aaaaaaaa")):
            with self.subTest(tag=release["tag_name"]):
                self.releases = FakeReleases()
                self.releases.records.append(release)
                self.assertFalse(self.run_preview())
                self.assertNotIn("create", self.releases.events)

    def test_existing_tag_is_never_overwritten_even_if_it_changes_during_upload(self):
        for before_create in (True, False):
            with self.subTest(before_create=before_create):
                self.releases = FakeReleases()
                if before_create:
                    self.releases.tag_target = "b" * 40
                else:
                    self.releases.after_upload = lambda api: setattr(api, "tag_target", "b" * 40)
                with self.assertRaisesRegex(ValueError, "another commit"):
                    self.run_preview()
                self.assertNotIn("publish", self.releases.events)
                if before_create:
                    self.assertNotIn("create", self.releases.events)

    def test_retention_keeps_ten_own_public_previews_and_every_other_release(self):
        self.releases.records = [published(number) for number in range(1, 13)]
        self.releases.records.extend((
            published(13, prerelease=False),
            published(14, draft=True),
            published(15, tag_name="other-preview-15"),
            published(16, body="Hand-created preview with a similar tag"),
        ))
        preview.prune_previews(self.releases, REPOSITORY)
        self.assertEqual({item["id"] for item in self.releases.records}, set(range(3, 17)))
        self.assertEqual([event for event in self.releases.events if event.startswith("delete:")], ["delete:2", "delete:1"])

    def test_retention_rechecks_draft_state_before_deleting(self):
        self.releases.records = [published(number) for number in range(1, 12)]
        self.releases.changed_record = 1
        with self.assertRaisesRegex(ValueError, "changed before cleanup"):
            preview.prune_previews(self.releases, REPOSITORY)
        self.assertFalse(any(event.startswith("delete:") for event in self.releases.events))

    def test_cli_commands_keep_previews_nonlatest_and_never_force_or_clobber(self):
        api = preview.GitHubReleases(REPOSITORY)
        with patch.object(preview.subprocess, "run") as run:
            api.create("preview-42-2-aaaaaaaa", SHA, "Checked build")
            api.upload("preview-42-2-aaaaaaaa", self.archive)
            api.publish("preview-42-2-aaaaaaaa")
            api.delete(123)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertIn("--draft", calls[0])
        self.assertIn("--prerelease", calls[0])
        self.assertIn("--latest=false", calls[0])
        self.assertIn("--latest=false", calls[2])
        self.assertIn("--draft=false", calls[2])
        self.assertFalse(any(argument in ("--clobber", "--force", "--cleanup-tag") for command in calls for argument in command))
        self.assertEqual(calls[3], ["gh", "api", "--method", "DELETE", "repos/SeaLoong/drcom4scut/releases/123"])

    def test_cli_tag_check_allows_missing_draft_tag_but_requires_exact_public_target(self):
        api = preview.GitHubReleases(REPOSITORY)
        tag = "preview-42-2-aaaaaaaa"
        with patch.object(api, "_query", return_value=[]):
            api.verify_tag_target(tag, SHA)
            with self.assertRaisesRegex(ValueError, "missing"):
                api.verify_tag_target(tag, SHA, required=True)
        reference = {"ref": "refs/tags/" + tag, "object": {"type": "commit", "sha": SHA}}
        with patch.object(api, "_query", return_value=[reference]):
            api.verify_tag_target(tag, SHA, required=True)
            with self.assertRaisesRegex(ValueError, "another commit"):
                api.verify_tag_target(tag, "b" * 40)


if __name__ == "__main__":
    unittest.main()
