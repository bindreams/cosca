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
from dataclasses import dataclass
from pathlib import Path

from scripts import devvm

GUESTS_DIR = Path(__file__).resolve().parent / "devvm" / "guests"
VAGRANT_GUESTS = ("linux-x64", "linux-arm64", "windows-x64")
BOX_RE = re.compile(r"^(?P<name>\S+) \((?P<provider>\w+)/(?P<arch>\w+)\)$")
URL_RE = re.compile(
    r"^https://vagrantcloud\.com/(?P<org>[^/]+)/boxes/(?P<box>[^/]+)/versions/(?P<version>[^/]+)"
    r"/providers/(?P<provider>\w+)/(?P<arch>\w+)/vagrant\.box$"
)


@dataclass(frozen=True)
class Pin:
    """One pinned box: a guest's box text in devvm.py, the metadata file and the Vagrantfile lines for it."""

    guest: str
    box_text: str
    metadata_file: str
    format: str  # the box format the pinned file has; vagrant-qemu asks for libvirt, Hyper-V for hyperv
    receiver: str  # what the Vagrantfile sets it on: `config` at the top level, `override` in a provider block

    @property
    def declares_arch(self) -> bool:
        return self.receiver == "config"

    @property
    def box_url_line(self) -> str:
        return f'{self.receiver}.vm.box_url = "file://#{{File.expand_path("{self.metadata_file}", __dir__)}}"'


QEMU_PINS = tuple(Pin(g, devvm.GUESTS[g].box, "box.json", "libvirt", "config") for g in VAGRANT_GUESTS)
HYPERV_PINS = (Pin("windows-x64", devvm.GUESTS["windows-x64"].hyperv_box, "box.hyperv.json", "hyperv", "override"),)
PINS = QEMU_PINS + HYPERV_PINS


def vagrantfile(guest: str) -> str:
    return (GUESTS_DIR / guest / "Vagrantfile").read_text(encoding="utf-8")


def setting(pin: Pin, key: str) -> str | None:
    m = re.search(rf'^\s*{pin.receiver}\.vm\.{key}\s*=\s*"([^"]*)"\s*$', vagrantfile(pin.guest), re.MULTILINE)
    return m.group(1) if m else None


def metadata(pin: Pin) -> dict:
    return json.loads((GUESTS_DIR / pin.guest / pin.metadata_file).read_text(encoding="utf-8"))


def pinned(pin: Pin) -> tuple[dict, dict, re.Match[str]]:
    """(metadata, its single provider entry, the parsed provider URL)."""
    meta = metadata(pin)
    [version] = meta["versions"]
    [provider] = version["providers"]
    url = URL_RE.match(provider["url"])
    assert url, provider["url"]
    return meta, provider, url


class VagrantfileAgreesWithGuestsTests(unittest.TestCase):
    def test_every_vagrant_box_guest_is_covered(self) -> None:
        on_disk = sorted(p.name for p in GUESTS_DIR.iterdir() if (p / "Vagrantfile").is_file())
        self.assertEqual(on_disk, sorted(VAGRANT_GUESTS))

    def test_every_hyperv_box_is_covered(self) -> None:
        with_box = sorted(name for name, guest in devvm.GUESTS.items() if guest.hyperv_box is not None)
        self.assertEqual(with_box, sorted(pin.guest for pin in HYPERV_PINS))

    def test_box_url_points_at_the_metadata_file(self) -> None:
        for pin in PINS:
            with self.subTest(guest=pin.guest, format=pin.format):
                self.assertIn(pin.box_url_line, vagrantfile(pin.guest))

    def test_provider_url_names_the_guests_box_provider_and_arch(self) -> None:
        for pin in PINS:
            with self.subTest(guest=pin.guest, format=pin.format):
                box = BOX_RE.match(pin.box_text)
                self.assertIsNotNone(box, pin.box_text)
                _, provider, url = pinned(pin)
                self.assertEqual(f"{url['org']}/{url['box']}", box["name"])
                self.assertEqual(provider["name"], pin.format)
                self.assertEqual(url["provider"], pin.format)
                self.assertEqual(url["arch"], box["arch"])
                self.assertEqual(provider["architecture"], box["arch"])
                if pin.declares_arch:
                    self.assertEqual(setting(pin, "box_architecture"), box["arch"])

    def test_box_is_a_local_name_carrying_the_version(self) -> None:
        for pin in PINS:
            with self.subTest(guest=pin.guest, format=pin.format):
                box = BOX_RE.match(pin.box_text)
                meta, _, url = pinned(pin)
                self.assertEqual(meta["versions"][0]["version"], url["version"])
                self.assertEqual(setting(pin, "box"), f"{box['name']}-{url['version']}")
                self.assertEqual(meta["name"], setting(pin, "box"))

    def test_checksum_is_a_sha512(self) -> None:
        for pin in PINS:
            with self.subTest(guest=pin.guest, format=pin.format):
                _, provider, _ = pinned(pin)
                self.assertEqual(provider["checksum_type"], "sha512")
                self.assertRegex(provider["checksum"], r"^[0-9a-f]{128}$")

    def test_vagrantfile_sets_no_setting_vagrant_would_ignore(self) -> None:
        """With a metadata `box_url`, these are not what pins the box; leaving them would mislead."""
        for pin in PINS:
            for key in ("box_version", "box_download_checksum", "box_download_checksum_type"):
                with self.subTest(guest=pin.guest, format=pin.format, key=key):
                    self.assertIsNone(setting(pin, key))


if __name__ == "__main__":
    unittest.main()
