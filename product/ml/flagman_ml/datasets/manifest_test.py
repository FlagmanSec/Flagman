import pytest

from flagman_ml.datasets.manifest import ManifestError, load_manifest, parse_size
from flagman_ml.testing import DATA


def write(tmp_path, files):
    path = tmp_path / "m.toml"
    path.write_text('dataset = "d"\npage = "https://example.org"\n' + files, encoding="utf-8")
    return path


def entry(name="a/flows.pcap", url="https://example.org/flows.pcap", extra=""):
    return f'[[files]]\nname = "{name}"\nurl = "{url}"\nkind = "pcap"\n{extra}\n'


@pytest.mark.parametrize("path", sorted((DATA / "manifests").glob("*.toml")), ids=lambda p: p.name)
def test_every_manifest_in_the_repository_loads(path):
    manifest = load_manifest(path)
    assert manifest.page.startswith("https://")


def test_listed_sizes_give_a_rough_number_of_bytes():
    assert parse_size("56M") == 56 * 1024**2
    assert parse_size("1.9G") == int(1.9 * 1024**3)
    assert parse_size("") == 0


def test_a_recorded_size_wins_over_the_listed_one(tmp_path):
    manifest = load_manifest(write(tmp_path, entry(extra='listed_size = "2K"\nbytes = 2000')))
    assert manifest.files[0].estimated_bytes() == 2000


@pytest.mark.parametrize("files, message", [
    (entry(name="../outside.pcap"), "plain relative path"),
    (entry(name="/etc/passwd"), "plain relative path"),
    (entry(name="sample/Neris.exe.zip"), "never download one"),
    (entry(url="https://example.org/only-exes-of-ctu-13.zip"), "never download one"),
    (entry(url="ftp://example.org/flows.pcap"), "must start with https://"),
    (entry(extra='sha256 = "abc"'), "64 hexadecimal"),
    (entry() + entry(), "appears twice"),
])
def test_unsafe_or_broken_entries_are_refused(tmp_path, files, message):
    with pytest.raises(ManifestError, match=message):
        load_manifest(write(tmp_path, files))


def test_files_are_chosen_by_name(tmp_path):
    manifest = load_manifest(write(tmp_path, entry() + entry(name="b/big.pcap")))
    assert [e.name for e in manifest.select()] == ["a/flows.pcap", "b/big.pcap"]
    assert [e.name for e in manifest.select(only=["b/big.pcap"])] == ["b/big.pcap"]
    assert [e.name for e in manifest.select(skip=["b/big.pcap"])] == ["a/flows.pcap"]
    with pytest.raises(ManifestError, match="no file named"):
        manifest.select(only=["c.pcap"])
