"""Installer tests using local files and a fake runtime."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader("veil_install", str(Path(__file__).resolve().parents[1] / "scripts/install"))
spec = importlib.util.spec_from_loader(loader.name, loader)
installer = importlib.util.module_from_spec(spec)
loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.asset = {"url": "https://invalid.example/asset", "sha256": hashlib.sha256(b"known").hexdigest()}

    def test_verified_cache_is_used_without_network(self):
        cached = self.cache / self.asset["sha256"]
        cached.write_bytes(b"known")
        with patch.object(installer.urllib.request, "urlopen", side_effect=AssertionError("network")):
            self.assertEqual(installer.fetch(self.asset, self.cache, False), cached)

    def test_corrupt_cache_fails_without_redownloading(self):
        (self.cache / self.asset["sha256"]).write_bytes(b"corrupt")
        with patch.object(installer.urllib.request, "urlopen", side_effect=AssertionError("network")):
            with self.assertRaisesRegex(RuntimeError, "corrupt download cache"):
                installer.fetch(self.asset, self.cache, False)

    def test_offline_cache_miss_does_not_attempt_network(self):
        with patch.object(installer.urllib.request, "urlopen", side_effect=AssertionError("network")):
            with self.assertRaisesRegex(RuntimeError, "offline cache miss"):
                installer.fetch(self.asset, self.cache, True)

    def test_bad_download_is_not_published_and_temporary_is_removed(self):
        import io
        with patch.object(installer.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong")):
            with self.assertRaisesRegex(RuntimeError, "download checksum mismatch"):
                installer.fetch(self.asset, self.cache, False)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_existing_prefix_and_dangling_symlink_are_never_overwritten(self):
        prefix = self.root / "prefix"
        prefix.mkdir()
        (prefix / "keep").write_text("original")
        with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"):
            installer.install(prefix, self.cache, True)
        self.assertEqual((prefix / "keep").read_text(), "original")
        prefix = self.root / "dangling"
        prefix.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"):
            installer.install(prefix, self.cache, True)
        self.assertTrue(prefix.is_symlink())

    def prepare_source(self):
        source = self.root / "source"
        source.mkdir()
        for name in ["README.md", "LICENSE"]:
            (source / name).write_text(name)
        (source / "docs").mkdir()
        (source / "docs/ARCHITECTURE.md").write_text("architecture")
        binary = source / "binary"
        binary.write_bytes(b"binary")
        payload = source / "runtime"
        payload.write_bytes(b"native runtime")
        archive = source / "runtime.tgz"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(payload, arcname="package/lib.so")
        archive_hash = installer.digest(archive)
        (self.cache / archive_hash).write_bytes(archive.read_bytes())
        asset = {"path": "lib/lib.so", "member": "package/lib.so", "sha256": installer.digest(payload)}
        (source / "assets.lock.json").write_text(json.dumps({
            "schema": 1, "asset_set": "test", "files": [],
            "runtime_archive": {"url": "https://invalid.example/archive", "sha256": archive_hash},
            "platforms": {"test-platform": {"runtime": "lib/lib.so", "files": [asset]}},
        }))
        return source, binary

    def test_successful_install_is_staged_verified_and_readable(self):
        source, binary = self.prepare_source()
        prefix = self.root / "prefix"
        observed = []
        def smoke(stage):
            self.assertFalse(prefix.exists())
            self.assertEqual((stage / "lib/lib.so").read_bytes(), b"native runtime")
            self.assertEqual(json.loads((stage / "manifest.json").read_text())["platform"], "test-platform")
            observed.append(stage)
        old_umask = os.umask(0o077)
        try:
            with patch.object(installer, "ROOT", source), \
                 patch.object(installer, "native_target", return_value=("test-host", "test-platform")), \
                 patch.object(installer, "build", return_value=(binary, "1.0")), \
                 patch.object(installer, "smoke_test", side_effect=smoke):
                installer.install(prefix, self.cache, True)
        finally:
            os.umask(old_umask)
        self.assertEqual(len(observed), 1)
        self.assertTrue((prefix / "bin/veil").is_file())
        self.assertEqual(prefix.stat().st_mode & 0o777, 0o755)
        self.assertEqual((prefix / "lib").stat().st_mode & 0o777, 0o755)
        self.assertEqual((prefix / "manifest.json").stat().st_mode & 0o777, 0o644)
        self.assertFalse((self.root / ".prefix.install-lock").exists())
        self.assertFalse(observed[0].exists())

    def test_failed_smoke_test_leaves_no_installation_or_lock(self):
        source, binary = self.prepare_source()
        prefix = self.root / "prefix"
        with patch.object(installer, "ROOT", source), \
             patch.object(installer, "native_target", return_value=("test-host", "test-platform")), \
             patch.object(installer, "build", return_value=(binary, "1.0")), \
             patch.object(installer, "smoke_test", side_effect=RuntimeError("bad native runtime")):
            with self.assertRaisesRegex(RuntimeError, "bad native runtime"):
                installer.install(prefix, self.cache, True)
        self.assertFalse(prefix.exists())
        self.assertFalse((self.root / ".prefix.install-lock").exists())
        self.assertFalse(list(self.root.glob(".prefix.stage-*")))

    def test_missing_assets_leave_no_prefix(self):
        source, _ = self.prepare_source()
        (self.cache / next(self.cache.iterdir()).name).unlink()
        with patch.object(installer, "ROOT", source), \
             patch.object(installer, "native_target", return_value=("test-host", "test-platform")):
            with self.assertRaisesRegex(RuntimeError, "offline cache miss"):
                installer.install(self.root / "prefix", self.cache, True)
        self.assertFalse((self.root / "prefix").exists())
        self.assertFalse((self.root / ".prefix.install-lock").exists())


if __name__ == "__main__":
    unittest.main()
