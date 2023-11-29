"""
Tests mwcp.Runner components.
"""
import textwrap

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


def test_yara_runner_sibling_dispatch(datadir):
    """
    Tests Github issue #40 where a file doesn't get processed because
    it was dispatched with a parent of an already processed sibling.
    """
    mwcp.register_parser_directory(str(datadir), source_name="test")

    # Test running SingleDispatch parser and see if we successfully get the Grandchild to be parsed.
    report = mwcp.run(data=b"matches parent", yara_repo=datadir / "yara_repo", recursive=True)
    assert report
    assert report.parser == "-"
    input_file = report.input_file
    assert input_file.description == "Parent"
    children = input_file.children
    assert len(children) == 2
    assert children[0].description == "Sibling 1"
    assert children[1].description == "Sibling 2"
    assert len(children[0].children) == 1
    # This was originally unidentified due to not being processed.
    assert children[0].children[0].description == "Grandchild"
    assert report.file_tree() == textwrap.dedent("""\
        <40b44905ee15a698e22f086c758a3981.bin (40b44905ee15a698e22f086c758a3981) : Parent>
        ├── <efd40a513a2b00d7354756967ff6b683.bin (efd40a513a2b00d7354756967ff6b683) : Sibling 1>
        │   └── <3ca5088d02dfb0fc668a0e2898ec3d93.bin (3ca5088d02dfb0fc668a0e2898ec3d93) : Grandchild>
        └── <aaaa145ac48779f3eafdb0e521d15b94.bin (aaaa145ac48779f3eafdb0e521d15b94) : Sibling 2>""")
