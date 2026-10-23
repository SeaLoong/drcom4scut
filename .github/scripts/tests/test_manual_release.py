"""Check that partial/corrupt manual uploads stay private and notes match assets."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
if not (HERE / "publish_release.py").is_file():
    HERE = HERE.parent
spec = importlib.util.spec_from_file_location("manual_release", HERE / "publish_release.py")
manual = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manual)
REPOSITORY = "SeaLoong/" + HERE.parents[1].name
SHA = "a" * 40


class FakeReleases:
    def __init__(self, corrupt=False, fail_upload=False):
        self.corrupt = corrupt
        self.fail_upload = fail_upload
        self.public = False
        self.record = None

    def verify_tag_target(self, tag, sha, *, required):
        assert required and sha == SHA

    def create(self, tag, sha, notes):
        self.record = {"tag_name": tag, "target_commitish": sha, "draft": True,
                       "prerelease": "-" in tag, "assets": []}
        self.notes = notes

    def upload(self, tag, path):
        if self.fail_upload:
            raise OSError("Simulated interrupted upload")
        self.record["assets"].append({"name": path.name, "state": "uploaded", "size": path.stat().st_size,
                                      "digest": "sha256:" + ("0" * 64 if self.corrupt else hashlib.sha256(path.read_bytes()).hexdigest())})

    def draft(self, tag):
        return self.record

    def publish(self, tag):
        self.public = True


class ManualReleaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dist = Path(directory.name)
        archive = self.dist / "checked-package.zip"
        archive.write_bytes(b"validated archive")
        (self.dist / "SHA256SUMS").write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
        self.environment = {
            "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_SHA": SHA,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SERVER_URL": "https://github.com",
            "RELEASE_TAG": "v1.2.3", "CREATE_DRAFT": "false",
        }

    def test_successful_complete_upload_can_publish(self):
        api = FakeReleases()
        manual.publish_manual(self.environment, self.dist, api)
        self.assertTrue(api.public)
        self.assertEqual(len(api.record["assets"]), 2)
        self.assertIn("开始使用", api.notes)

    def test_requested_draft_and_interrupted_or_corrupt_uploads_stay_private(self):
        api = FakeReleases()
        manual.publish_manual(dict(self.environment, CREATE_DRAFT="true"), self.dist, api)
        self.assertFalse(api.public)
        for api in (FakeReleases(corrupt=True), FakeReleases(fail_upload=True)):
            with self.assertRaises((ValueError, OSError)):
                manual.publish_manual(self.environment, self.dist, api)
            self.assertFalse(api.public)

    def test_manual_publishing_rejects_pushes_invalid_tags_and_unknown_draft_values(self):
        for fields in ({"GITHUB_EVENT_NAME": "push"}, {"RELEASE_TAG": "../tag"}, {"CREATE_DRAFT": "maybe"}):
            api = FakeReleases()
            with self.assertRaises(ValueError):
                manual.publish_manual(dict(self.environment, **fields), self.dist, api)
            self.assertIsNone(api.record)

    def test_manual_prerelease_never_becomes_latest(self):
        api = manual.ManualReleases(REPOSITORY, True)
        with patch.object(api, "_run") as run:
            api.publish("v1.2.3-rc.1")
        self.assertIn("--latest=false", run.call_args.args)
        self.assertIn("--prerelease=true", run.call_args.args)

    def test_notes_link_to_every_platform_and_commit_pinned_help(self):
        notes = manual.preview.release_notes.render(REPOSITORY, SHA, "v1.2.3")
        platforms = json.loads((HERE / "platforms.json").read_text())
        for platform in platforms:
            target = platform.get("runtime", platform.get("target"))
            self.assertIn(target, notes)
        self.assertIn(f"/blob/{SHA}/", notes)
        self.assertIn("SHA256SUMS", notes)


if __name__ == "__main__":
    unittest.main()
