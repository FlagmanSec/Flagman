import pandas as pd

from flagman_ml.files import read_table, replace_atomically, sha256_of, write_table


def test_the_checksum_names_the_exact_bytes(tmp_path):
    path = tmp_path / "hello.txt"
    path.write_bytes(b"hello\n")
    # The same value as `sha256sum hello.txt` on Linux.
    assert sha256_of(path) == (
        "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
    )


def test_a_finished_file_replaces_the_old_one(tmp_path):
    final = tmp_path / "labels.parquet"
    final.write_text("old")
    tmp = tmp_path / "labels.parquet.part"
    tmp.write_text("new")
    replace_atomically(tmp, final)
    assert final.read_text() == "new"
    assert not tmp.exists()


def test_a_table_keeps_its_provenance_under_its_own_key(tmp_path):
    path = tmp_path / "table.parquet"
    write_table(pd.DataFrame({"row": [0, 1]}), path, "flagman.example", {"made_by": "a test"})
    table, provenance = read_table(path, "flagman.example")
    assert table["row"].tolist() == [0, 1]
    assert provenance == {"made_by": "a test"}
    assert read_table(path, "flagman.other") is None  # another kind of file
    assert not (tmp_path / "table.parquet.part").exists()
