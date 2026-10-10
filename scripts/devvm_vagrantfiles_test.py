"""Each Vagrant-box guest's Vagrantfile and box.json agree with its GUESTS entry in devvm.py.

Vagrant checks a downloaded box only against the checksum in the box *metadata* it was added from.
`config.vm.box_download_checksum` applies to a direct box file URL, which Vagrant Cloud's
JSON-negotiating redirect makes unusable, and a box named from the catalog is checked only against
the catalog's own checksum (none for two of ours). So the pin lives in `box.json`, which the
Vagrantfile points `box_url` at. Host-safe: reads files only.

Run with: python3 -m unittest scripts.devvm_vagrantfiles_test -v
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from scripts import devvm

GUESTS_DIR = Path(__file__).resolve().parent / "devvm" / "guests"
VAGRANT_GUESTS = ("linux-x64", "linux-arm64", "windows-x64")
BOX_RE = re.compile(r"^(?P<name>\S+) \((?P<provider>\w+)/(?P<arch>\w+)\)$")
URL_RE = re.compile(
    r"^https://vagrantcloud\.com/(?P<org>[^/]+)/boxes/(?P<box>[^/]+)/versions/(?P<version>[^/]+)"
    r"/providers/(?P<provider>\w+)/(?P<arch>\w+)/vagrant\.box$"
)
# vagrant-qemu asks for a box of this format, so the file pinned is the catalog's libvirt one.
BOX_FORMAT = "libvirt"
BOX_URL_LINE = 'config.vm.box_url = "file://#{File.expand_path("box.json", __dir__)}"'


def vagrantfile(guest: str) -> str:
    return (GUESTS_DIR / guest / "Vagrantfile").read_text(encoding="utf-8")


def setting(guest: str, key: str) -> str | None:
    m = re.search(rf'^\s*config\.vm\.{key}\s*=\s*"([^"]*)"\s*$', vagrantfile(guest), re.MULTILINE)
    return m.group(1) if m else None


def metadata(guest: str) -> dict:
    return json.loads((GUESTS_DIR / guest / "box.json").read_text(encoding="utf-8"))


def pinned(guest: str) -> tuple[dict, dict, re.Match[str]]:
    """(metadata, its single provider entry, the parsed provider URL)."""
    meta = metadata(guest)
    [version] = meta["versions"]
    [provider] = version["providers"]
    url = URL_RE.match(provider["url"])
    assert url, provider["url"]
    return meta, provider, url


class VagrantfileAgreesWithGuestsTests(unittest.TestCase):
    def test_every_vagrant_box_guest_is_covered(self) -> None:
        on_disk = sorted(p.name for p in GUESTS_DIR.iterdir() if (p / "Vagrantfile").is_file())
        self.assertEqual(on_disk, sorted(VAGRANT_GUESTS))

    def test_box_url_points_at_box_json(self) -> None:
        for guest in VAGRANT_GUESTS:
            with self.subTest(guest=guest):
                self.assertIn(BOX_URL_LINE, vagrantfile(guest))

    def test_provider_url_names_the_guests_box_provider_and_arch(self) -> None:
        for guest in VAGRANT_GUESTS:
            with self.subTest(guest=guest):
                box = BOX_RE.match(devvm.GUESTS[guest].box)
                self.assertIsNotNone(box, devvm.GUESTS[guest].box)
                _, provider, url = pinned(guest)
                self.assertEqual(f"{url['org']}/{url['box']}", box["name"])
                self.assertEqual(provider["name"], BOX_FORMAT)
                self.assertEqual(url["provider"], BOX_FORMAT)
                self.assertEqual(url["arch"], box["arch"])
                self.assertEqual(provider["architecture"], box["arch"])
                self.assertEqual(setting(guest, "box_architecture"), box["arch"])

    def test_box_is_a_local_name_carrying_the_version(self) -> None:
        for guest in VAGRANT_GUESTS:
            with self.subTest(guest=guest):
                box = BOX_RE.match(devvm.GUESTS[guest].box)
                meta, _, url = pinned(guest)
                self.assertEqual(meta["versions"][0]["version"], url["version"])
                self.assertEqual(setting(guest, "box"), f"{box['name']}-{url['version']}")
                self.assertEqual(meta["name"], setting(guest, "box"))

    def test_checksum_is_a_sha512(self) -> None:
        for guest in VAGRANT_GUESTS:
            with self.subTest(guest=guest):
                _, provider, _ = pinned(guest)
                self.assertEqual(provider["checksum_type"], "sha512")
                self.assertRegex(provider["checksum"], r"^[0-9a-f]{128}$")

    def test_vagrantfile_sets_no_setting_vagrant_would_ignore(self) -> None:
        """With a metadata `box_url`, these are not what pins the box; leaving them would mislead."""
        for guest in VAGRANT_GUESTS:
            for key in ("box_version", "box_download_checksum", "box_download_checksum_type"):
                with self.subTest(guest=guest, key=key):
                    self.assertIsNone(setting(guest, key))


if __name__ == "__main__":
    unittest.main()
