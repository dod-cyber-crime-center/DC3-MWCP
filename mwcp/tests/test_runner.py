"""
Tests mwcp.Runner components.
"""

import mwcp


def test_running_parser_class():
    from mwcp import Parser

    class TestParser(Parser):
        DESCRIPTION = "Test"

    report = mwcp.run(TestParser, data=b"test")
    assert report
    assert report.parser == "TestParser"


def test_yara_runner(datadir):
    mwcp.register_entry_points()

    # File should map to foo parser.
    report = mwcp.run(data=b"mapped file", yara_repo=datadir / "yara_repo", recursive=False)
    assert report
    # Report "parser" will be "-" because it was initially unknown, but the parser mapped
    # to the input file should be foo.
    assert report.parser == "-"
    assert report.input_file.description == "Foo"
    assert report.input_file.parser.name == "foo.Foo"


def test_yara_runner_recursive(datadir):
    mwcp.register_parser_directory(str(datadir), source_name="test")

    # Initial file should map to FileA and residual to FileB.
    # Recursion detection should take effect.
    report = mwcp.run(data=b"matches file a", yara_repo=datadir / "yara_repo", recursive=True)
    assert report
    assert report.parser == "-"
    assert report.input_file.description == "File A"
    residual_file = report.input_file.children[0]
    assert residual_file.description == "File B"

    # Recursion will not take effect.
    report = mwcp.run(data=b"matches file a", yara_repo=datadir / "yara_repo", recursive=False)
    assert report
    assert report.parser == "-"
    assert report.input_file.description == "File A"
    residual_file = report.input_file.children[0]
    assert residual_file.description == "Unidentified file"
