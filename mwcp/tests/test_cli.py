"""
Tests the CLI tools.
"""

import hashlib
import json
import os
import re
import sys

from click.testing import CliRunner
import pytest
import pathlib

import mwcp
from mwcp import cli


@pytest.fixture(autouse=True)
def reset():
    """Ensures registry and config is reset for each test."""
    mwcp.clear_registry()
    mwcp.config.clear()


def test_parse(tmp_path, datadir):
    """Test running a parser"""
    runner = CliRunner(mix_stderr=False)

    with runner.isolated_filesystem(tmp_path):

        test_file = "test.txt"
        with open(test_file, "wb") as fp:
            fp.write(b"This is some test data!")

        # Run the foo parser on the test input file.
        ret = runner.invoke(cli.main, ["parse", "foo", test_file])
        print(ret.stdout)
        print(ret.stderr, file=sys.stderr)
        assert ret.exit_code == 0

        expected = (datadir / "parse.txt").read_text("utf-8")
        assert ret.stdout == expected

        output_file = pathlib.Path(f"{test_file}_mwcp_output", "5eb63_fooconfigtest.txt")
        assert output_file.exists()

        # Test the "--no-output-files" flag.
        output_file.unlink()
        assert not output_file.exists()
        ret = runner.invoke(cli.main, ["parse", "--no-output-files", "foo", test_file])
        assert ret.exit_code == 0
        # We should still not have the output file
        assert not output_file.exists()

        # Test the json formatting
        ret = runner.invoke(cli.main, ["parse", "--no-output-files", "-f", "json", "foo", test_file])
        print(ret.stdout)
        print(ret.stderr, file=sys.stderr)
        assert ret.exit_code == 0

        expected = (datadir / "parse.json").read_text("utf-8").replace("MWCP_VERSION", mwcp.__version__)
        assert ret.stdout == expected


def test_list(tmp_path, make_sample_parser):
    """
    Tests displaying a list of parsers.

    (This is also where we test the parser registration flags.)
    """
    runner = CliRunner(mix_stderr=False)

    with runner.isolated_filesystem(tmp_path):

        # First ensure our foo parser is registered via entry_points.
        ret = runner.invoke(cli.main, ["list", "--json"])
        print(ret.stderr, file=sys.stderr)
        assert ret.exit_code == 0

        results = json.loads(ret.stdout, encoding="utf8")
        assert len(results) > 1
        for name, source_name, author, description in results:
            if name == u"foo" and source_name == u"dc3":
                assert author == u"DC3"
                assert description == u"example parser that works on any file"
                break
        else:
            pytest.fail("Sample parser was not listed.")

        parser_file, config_file = make_sample_parser()
        parser_dir = parser_file.dirname

        # Now try adding the Sample parser using the --parser-dir flag.
        ret = runner.invoke(cli.main, [
            "--parser-dir", str(parser_dir),
            "--parser-config", str(config_file),
            "list", "--json",
        ])
        print(ret.stderr, file=sys.stderr)
        assert ret.exit_code == 0

        # FIXME: This breaks if user has set up a PARSER_SOURCE in the configuration file.
        results = json.loads(ret.stdout, encoding="utf8")
        assert len(results) > 1
        for name, source_name, author, description in results:
            if source_name == str(parser_dir):
                assert name == u"Sample"
                assert author == u"Mr. Tester"
                assert description == u"A test parser"
                break
        else:
            pytest.fail("Sample parser from parser directory was not listed.")

        # If we set --parser-source we should only get our registered parser from the directory.
        ret = runner.invoke(cli.main, [
            "--parser-dir", str(parser_dir),
            "--parser-config", str(config_file),
            "--parser-source", str(parser_dir),
            "list", "--json"
        ])
        print(ret.stderr, file=sys.stderr)
        assert ret.exit_code == 0

        results = json.loads(ret.stdout, encoding="utf8")
        assert results == [
            [u"Sample", str(parser_dir), u"Mr. Tester", u"A test parser"]
        ]

        # Now try adding the config_file path to the __init__.py file in order to avoid having
        # to manually use the --parser-config flag.
        init_file = pathlib.Path(parser_dir) / "__init__.py"
        init_file.write_text(f"config = {str(config_file)!r}", "utf8")
        ret = runner.invoke(cli.main, [
            "--parser-dir", str(parser_dir),
            "--parser-source", str(parser_dir),
            "list", "--json",
        ])
        print(ret.stderr, file=sys.stderr)
        assert ret.exit_code == 0

        results = json.loads(ret.stdout, encoding="utf8")
        assert results == [
            [u"Sample", str(parser_dir), u"Mr. Tester", u"A test parser"]
        ]


def test_csv_legacy(tmp_path, datadir):
    """Tests the csv feature."""
    input_files = ["file1.exe", "file2.exe"]
    results = [
        {
            "other": {"field1": "value1", "field2": ["value2", "value3"]},
            "outputfile": [["out_name", "out_desc", "out_md5"], ["out_name2", "out_desc2", "out_md52"]],
            "address": ["https://google.com", "ftp://amazon.com"]
        },
        {
            "a": ["b", "c"],
        }
    ]
    csv_file = tmp_path / "test.csv"

    cli._write_csv(input_files, results, str(csv_file))

    expected = (datadir / "csv_legacy.csv").read_text("utf-8")
    actual = csv_file.read_text("utf-8")
    actual = re.sub('\n[^"]*?,', "\n[TIMESTAMP],", actual)
    assert actual == expected


def test_csv_cli(tmp_path, datadir):
    """Tests the csv feature on the command line."""
    runner = CliRunner(mix_stderr=False)

    with runner.isolated_filesystem(tmp_path):

        with open("test.txt", "wb") as fp:
            fp.write(b"This is some test data!")

        ret = runner.invoke(cli.main, [
            "parse", "foo", "test.txt",
            "--no-output-files",
            "--format", "csv",
        ], catch_exceptions=False)
        print(ret.stdout)
        print(ret.stderr, file=sys.stderr)
        assert ret.exit_code == 0

        expected = (datadir / "csv_cli.csv").read_text()
        assert ret.stdout == expected


def test_add_testcase(tmp_path, datadir):
    """Tests adding a parser testcase."""
    runner = CliRunner(mix_stderr=False)

    malware_repo = tmp_path / "malware_repo"
    malware_repo.mkdir()
    test_case_dir = tmp_path / "testcases"
    test_case_dir.mkdir()
    (test_case_dir / "dc3").mkdir()  # directory for parser source must also be created
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"This is some test data!")

    # Add a test case for our foo parser.
    ret = runner.invoke(cli.main, [
        "test", "foo",
        "--testcase-dir", str(test_case_dir),
        "--malware-repo", str(malware_repo),
        "--add", str(test_file),
    ], catch_exceptions=False)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.exit_code == 0

    # Ensure test file got placed in the right location.
    test_sample = malware_repo / "fb84" / "fb843efb2ffec987db12e72ca75c9ea2"
    assert test_sample.exists()
    assert test_sample.read_bytes() == test_file.read_bytes()

    # Ensure the test case was created correctly.
    test_case_file = test_case_dir / "dc3" / "foo" / "fb843efb2ffec987db12e72ca75c9ea2.json"
    assert test_case_file.exists()
    expected = (datadir / "fb843efb2ffec987db12e72ca75c9ea2.json").read_text().replace("MWCP_VERSION", mwcp.__version__)
    assert test_case_file.read_text() == expected

    # Now test that it ignores a second add of the same file.
    ret = runner.invoke(cli.main, [
        "test", "foo",
        "--testcase-dir", str(test_case_dir),
        "--malware-repo", str(malware_repo),
        "--add", str(test_file),
    ], catch_exceptions=False)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.exit_code == 0
    assert ret.stderr.splitlines()[-1] == (
        f"[-] (MainProcess:mwcp.testing): Test case for {test_file} already exists in {test_case_file}"
    )
    assert test_case_file.read_text() == expected

    # Now test force updating the results.
    ret = runner.invoke(cli.main, [
        "test", "foo",
        "--testcase-dir", str(test_case_dir),
        "--malware-repo", str(malware_repo),
        "--update",
        "--add", str(test_file),
    ], catch_exceptions=False)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.exit_code == 0
    # Since it would be too hard to dynamically change what the parser does, just ensure
    # we get the right stderr and the testcase hasn't changed.
    assert ret.stderr.splitlines()[-1] == (
        f"[+] (MainProcess:mwcp.testing): Adding results for {test_file} in {test_case_file}"
    )
    assert test_case_file.read_text() == expected

    # Now test the deletion of the test case.
    ret = runner.invoke(cli.main, [
        "test", "foo",
        "--testcase-dir", str(test_case_dir),
        "--malware-repo", str(malware_repo),
        "--delete", str(test_file),
    ], catch_exceptions=False)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.exit_code == 0

    # Make sure we did NOT remove the file from the malware repo.
    assert test_sample.exists()
    assert test_sample.read_bytes() == test_file.read_bytes()

    # Check that the test case has been removed.
    assert not test_case_file.exists()


def test_add_filelist_testcase(tmp_path):
    """Tests bulk adding testcases with --add-filelist flag."""
    runner = CliRunner(mix_stderr=False)

    malware_repo = tmp_path / "malware_repo"
    malware_repo.mkdir()
    test_case_dir = tmp_path / "testcases"
    test_case_dir.mkdir()
    (test_case_dir / "dc3").mkdir()  # directory for parser source must also be created

    # Create a file list of paths.
    filelist = []
    for i in range(10):
        file = tmp_path / f"file_{i}"
        data = f"this is file {i}".encode("utf8")
        file.write_bytes(data)
        filelist.append((str(file), hashlib.md5(data).hexdigest()))

    filelist_txt = tmp_path / "filelist.txt"
    filelist_txt.write_text(u"\n".join(file_path for file_path, _ in filelist), "utf8")

    # Add a test case for our sample parser.
    ret = runner.invoke(cli.main, [
        "test", "foo",
        "--testcase-dir", str(test_case_dir),
        "--malware-repo", str(malware_repo),
        "--add-filelist", str(filelist_txt),
    ], catch_exceptions=False)
    print(ret.stdout)
    print(ret.stderr, file=sys.stderr)
    assert ret.exit_code == 0

    # Ensure a sample and test case was added for each file.
    for _, md5 in filelist:
        assert (malware_repo / md5[:4] / md5).exists()
        assert (test_case_dir / "dc3" / "foo" / f"{md5}.json").exists()
