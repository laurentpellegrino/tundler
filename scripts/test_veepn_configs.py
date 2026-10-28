"""Regression checks for the VeePN release archive; no credentials required."""
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "veepn_updater", Path(__file__).with_name("update-veepn-configs.py"))
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.raw = self.root / "upstream.zip"
        self.out = self.root / "output.zip"
        self.entries = [(f"configs/place-{i}.{proto}.veepn.com.ovpn",
                         b"client\nremote 192.0.2.1 1194\n")
                        for i in range(50) for proto in ("tcp", "udp")]

    def write_zip(self, entries, year=2026):
        with zipfile.ZipFile(self.raw, "w") as archive:
            for name, data in entries:
                archive.writestr(zipfile.ZipInfo(name, (year, 1, 1, 0, 0, 0)), data)

    def test_flat_deterministic_archive(self):
        self.write_zip(self.entries)
        self.assertEqual(updater.normalize_archive(self.raw, self.out), 100)
        first = self.out.read_bytes()
        self.write_zip(reversed(self.entries), year=2025)
        updater.normalize_archive(self.raw, self.out)
        self.assertEqual(first, self.out.read_bytes())
        with zipfile.ZipFile(self.out) as archive:
            self.assertTrue(all("/" not in name for name in archive.namelist()))

    def test_same_size_content_change_is_detected(self):
        self.write_zip(self.entries)
        updater.normalize_archive(self.raw, self.out)
        first = self.out.read_bytes()
        name, data = self.entries[0]
        self.entries[0] = (name, data.replace(b"192.0.2.1", b"192.0.2.2"))
        self.write_zip(self.entries)
        updater.normalize_archive(self.raw, self.out)
        self.assertNotEqual(first, self.out.read_bytes())

    def test_rejects_invalid_archives_preserving_existing_output(self):
        invalid = [
            self.entries[:2],
            [(f"configs/place-{i}.tcp.veepn.com.ovpn", data)
             for i, (_, data) in enumerate(self.entries)],
            self.entries + [("other/place-0.tcp.veepn.com.ovpn", b"remote x\n")],
            self.entries + [("unrelated.ovpn", b"remote x\n")],
            [(name, b"<html>not a config</html>") for name, _ in self.entries],
        ]
        self.out.write_bytes(b"existing release")
        for entries in invalid:
            with self.subTest(first=entries[0][0], count=len(entries)):
                self.write_zip(entries)
                with self.assertRaises(ValueError):
                    updater.normalize_archive(self.raw, self.out)
                self.assertEqual(self.out.read_bytes(), b"existing release")

    def test_rejects_html_instead_of_zip(self):
        self.raw.write_text("<html>Cloudflare challenge</html>")
        with self.assertRaises(zipfile.BadZipFile):
            updater.normalize_archive(self.raw, self.out)
        self.assertFalse(self.out.exists())

    def test_download_completion(self):
        download_dir = self.root / "downloads"
        download_dir.mkdir()
        self.assertIsNone(updater.completed_download(download_dir))
        self.write_zip(self.entries)
        pending = download_dir / "configs.zip.crdownload"
        pending.write_bytes(self.raw.read_bytes())
        self.assertIsNone(updater.completed_download(download_dir))
        ready = pending.with_suffix("")
        pending.rename(ready)
        self.assertEqual(updater.completed_download(download_dir), ready)


if __name__ == "__main__":
    unittest.main()
