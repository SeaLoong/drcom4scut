"""Check that partial/corrupt manual uploads stay private and notes match assets."""
import hashlib
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_fixtures import add_bundles
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
        self.created = 0
        self.uploaded = []
        self.fail_after = None
        self.after_lookup = None

    def verify_tag_target(self, tag, sha, *, required):
        assert required and sha == SHA

    def create(self, tag, sha, notes):
        if self.record is not None:
            raise RuntimeError("Release already exists")
        self.created += 1
        self.record = {"id": 17, "url": f"https://api.github.com/repos/{REPOSITORY}/releases/17",
                       "tag_name": tag, "target_commitish": sha, "draft": True,
                       "prerelease": "-" in tag, "assets": []}
        self.notes = notes

    def existing(self, tag):
        record = copy.deepcopy(self.record)
        if self.after_lookup:
            self.after_lookup(self.record)
        return record

    def upload(self, tag, path):
        if self.fail_upload or self.fail_after == len(self.uploaded):
            raise OSError("Simulated interrupted upload")
        self.uploaded.append(path.name)
        self.record["assets"].append({"name": path.name, "state": "uploaded", "size": path.stat().st_size,
                                      "digest": "sha256:" + ("0" * 64 if self.corrupt else hashlib.sha256(path.read_bytes()).hexdigest())})

    def draft(self, tag):
        return self.record

    def publish(self, tag):
        self.public = True
        self.record["draft"] = False


class ManualReleaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dist = Path(directory.name)
        archive = self.dist / "checked-package.zip"
        archive.write_bytes(b"validated archive")
        (self.dist / "SHA256SUMS").write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
        self.bundles = add_bundles(self.dist, REPOSITORY, HERE.parents[1])
        sample = next(iter(self.bundles.values()))
        self.tag = "v" + sample["gui_version" if REPOSITORY.endswith("GUI") else "core_version"]
        self.environment = {
            "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_SHA": SHA,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SERVER_URL": "https://github.com",
            "RELEASE_TAG": self.tag, "CREATE_DRAFT": "false",
        }

    def test_successful_complete_upload_can_publish(self):
        api = FakeReleases()
        manual.publish_manual(self.environment, self.dist, api)
        self.assertTrue(api.public)
        self.assertEqual(len(api.record["assets"]), 8)
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
        for fields in ({"GITHUB_EVENT_NAME": "push"}, {"RELEASE_TAG": "../tag"},
                       {"RELEASE_TAG": "v99.88.77"}, {"CREATE_DRAFT": "maybe"}):
            api = FakeReleases()
            with self.assertRaises(ValueError):
                manual.publish_manual(dict(self.environment, **fields), self.dist, api)
            self.assertIsNone(api.record)

    def test_missing_incomplete_or_mismatched_bundle_index_never_creates_a_release(self):
        path = self.dist / "BUNDLE-INDEX.json"
        original = path.read_text()
        for change in ("missing", "runtime", "digest", "filename"):
            index = json.loads(original)
            if change == "runtime": index.pop("linux-arm64")
            elif change == "digest": index["win-x64"]["sha256"] = "0" * 64
            elif change == "filename": index["win-x64"]["filename"] = "unverified.zip"
            path.write_text(json.dumps(index))
            if change == "missing": path.unlink()
            api = FakeReleases()
            with self.subTest(change=change), self.assertRaises(ValueError):
                manual.publish_manual(self.environment, self.dist, api)
            self.assertIsNone(api.record)
            self.assertFalse(api.public)

    def test_interrupted_upload_resumes_only_missing_assets_without_recreating_or_clobbering(self):
        api = FakeReleases()
        api.fail_after = 2
        with self.assertRaisesRegex(OSError, "interrupted"):
            manual.publish_manual(self.environment, self.dist, api)
        existing = copy.deepcopy(api.record["assets"])
        self.assertEqual(len(existing), 2)
        self.assertTrue(api.record["draft"])
        api.fail_after = None
        manual.publish_manual(self.environment, self.dist, api)
        self.assertEqual(api.created, 1)
        self.assertEqual(len(api.uploaded), len(set(api.uploaded)))
        self.assertEqual(api.record["assets"][:2], existing)
        self.assertEqual(len(api.record["assets"]), 8)
        self.assertTrue(api.public)

    def test_complete_requested_draft_can_be_published_without_uploading_again(self):
        api = FakeReleases()
        manual.publish_manual(dict(self.environment, CREATE_DRAFT="true"), self.dist, api)
        uploaded = list(api.uploaded)
        manual.publish_manual(self.environment, self.dist, api)
        self.assertEqual(api.created, 1)
        self.assertEqual(api.uploaded, uploaded)
        self.assertTrue(api.public)

    def test_resumed_upload_rechecks_a_draft_published_after_lookup(self):
        api = FakeReleases()
        api.fail_after = 2
        with self.assertRaises(OSError):
            manual.publish_manual(self.environment, self.dist, api)
        uploaded = list(api.uploaded)
        api.fail_after = None
        api.after_lookup = lambda record: record.update(draft=False)
        with self.assertRaisesRegex(ValueError, "identity or state changed"):
            manual.publish_manual(self.environment, self.dist, api)
        self.assertEqual(api.uploaded, uploaded)
        self.assertEqual(api.created, 1)
        self.assertFalse(api.public)

    def test_unrelated_public_or_changed_drafts_are_never_modified(self):
        changes = {
            "repository": lambda record: record.update(url="https://api.github.com/repos/other/repository/releases/17"),
            "tag": lambda record: record.update(tag_name="v99.88.77"),
            "commit": lambda record: record.update(target_commitish="b" * 40),
            "published": lambda record: record.update(draft=False),
            "prerelease": lambda record: record.update(prerelease=not record["prerelease"]),
            "digest": lambda record: record["assets"][0].update(digest="sha256:" + "0" * 64),
            "size": lambda record: record["assets"][0].update(size=1),
            "uploading": lambda record: record["assets"][0].update(state="new"),
            "attachment": lambda record: record["assets"].append({"name": "user-notes.txt"}),
            "duplicate": lambda record: record["assets"].append(copy.deepcopy(record["assets"][0])),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                api = FakeReleases()
                manual.publish_manual(dict(self.environment, CREATE_DRAFT="true"), self.dist, api)
                change(api.record)
                before = copy.deepcopy(api.record)
                uploaded = list(api.uploaded)
                with self.assertRaises(ValueError):
                    manual.publish_manual(self.environment, self.dist, api)
                self.assertEqual(api.record, before)
                self.assertEqual(api.uploaded, uploaded)
                self.assertEqual(api.created, 1)
                self.assertFalse(api.public)

    def test_existing_release_lookup_refetches_exact_identity_and_rejects_duplicate_tags(self):
        api = manual.ManualReleases(REPOSITORY, False)
        record = {"id": 17, "tag_name": self.tag}
        with patch.object(api, "list", return_value=[dict(record, tag_name="another-tag")]), patch.object(api, "get") as get:
            self.assertIsNone(api.existing(self.tag))
            get.assert_not_called()
        with patch.object(api, "list", return_value=[record]), patch.object(api, "get", return_value=record) as get:
            self.assertEqual(api.existing(self.tag), record)
            get.assert_called_once_with(17)
        with patch.object(api, "list", return_value=[record, record]), self.assertRaisesRegex(ValueError, "Duplicate"):
            api.existing(self.tag)

    def test_manual_prerelease_never_becomes_latest(self):
        api = manual.ManualReleases(REPOSITORY, True)
        with patch.object(api, "_run") as run:
            api.publish("v1.2.3-rc.1")
        self.assertIn("--latest=false", run.call_args.args)
        self.assertIn("--prerelease=true", run.call_args.args)

    def test_notes_link_to_every_platform_and_commit_pinned_help(self):
        notes = manual.preview.release_notes.render(REPOSITORY, SHA, "v1.2.3", bundles=self.bundles)
        for item in self.bundles.values():
            self.assertIn(f"[`{item['filename']}`](https://github.com/{REPOSITORY}/releases/download/v1.2.3/{item['filename']})", notes)
        if not REPOSITORY.endswith("GUI"):
            for platform in json.loads((HERE / "platforms.json").read_text()):
                if platform["openwrt"]:
                    self.assertIn(platform["target"], notes)
                else:
                    self.assertNotIn(platform["target"], notes)
        self.assertIn(f"/blob/{SHA}/", notes)
        self.assertIn("SHA256SUMS", notes)


if __name__ == "__main__":
    unittest.main()
