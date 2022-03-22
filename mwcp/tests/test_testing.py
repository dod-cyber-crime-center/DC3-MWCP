
import mwcp
from mwcp import testing


def test_get_malware_repo_path(tmp_path):
    """Tests generating malware repo path."""
    malware_repo = tmp_path / "malware_repo"
    malware_repo.mkdir()
    mwcp.config["MALWARE_REPO"] = str(malware_repo)

    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"This is some test data!")
    testing.add_to_malware_repo(test_file)

    expected_path = malware_repo / "fb84" / "fb843efb2ffec987db12e72ca75c9ea2"

    # Test with hashing a file.
    sample_path = testing.get_path_in_malware_repo(test_file)
    assert sample_path == expected_path

    # Test with md5
    sample_path = testing.get_path_in_malware_repo(md5="fb843efb2ffec987db12e72ca75c9ea2")
    assert sample_path == expected_path

    # Test with partial md5
    sample_path = testing.get_path_in_malware_repo(md5="fb843e")
    assert sample_path == expected_path


def test_add_to_malware_repo(tmp_path):
    """Tests adding a file to the malware repo."""
    malware_repo = tmp_path / "malware_repo"
    malware_repo.mkdir()
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"This is some test data!")

    mwcp.config["MALWARE_REPO"] = str(malware_repo)
    sample_path = testing.add_to_malware_repo(test_file)
    expected_sample_path = malware_repo / "fb84" / "fb843efb2ffec987db12e72ca75c9ea2"
    assert sample_path == expected_sample_path
    assert expected_sample_path.exists()
    assert expected_sample_path.read_bytes() == test_file.read_bytes()


def test_iter_md5s():
    """Tests obtaining md5s for a parser based on test cases"""
    mwcp.register_entry_points()
    mwcp.config["TESTCASE_DIR"] = None  # need to clear any previously set testcase_dir from a previous unit test.
    assert list(testing.iter_md5s("foo")) == ["f144899b86766688991c5d0d10902f4a"]
    assert list(testing.iter_md5s("bogus")) == []
