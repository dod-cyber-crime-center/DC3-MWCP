import pytest

import mwcp


def pytest_configure(config):
    """
    Registers custom markers.
    """
    config.addinivalue_line(
        "markers", "parsers: mark to only test parsers"
    )


def pytest_addoption(parser):
    """
    Creates CLI options for setting testcase_dir and malware_repo.
    """
    parser.addoption(
        "--testcase-dir", action="store",
        help="Directory containing JSON test case files for parser tests."
    )
    parser.addoption(
        "--malware-repo", action="store",
        help="Directory containing malware samples for parser tests."
    )


def pytest_make_parametrize_id(config, val, argname):
    """
    Hook id creation to convert legacy name to something more helpful than just "True"/"False".
    """
    if "legacy" in argname:
        return "legacy" if val else "new"



@pytest.fixture
def test_file(tmpdir):
    """Fixture for providing a test file to pass to mwcp."""
    file_path = tmpdir / 'test.txt'
    file_path = file_path.write_binary(b'This is some test data!')
    return file_path


@pytest.fixture
def test_dir(tmpdir):
    """Fixture for providing a test directory to pass to mwcp."""
    directory = tmpdir.mkdir('test_dir')
    for i in range(5):
        file_path = directory / 'test_{}.txt'.format(i)
        file_path.write_binary(b"This is some test data!")
    return directory


# language=Python
TEST_PARSER = u'''
from mwcp import Parser

class Downloader(Parser):
    DESCRIPTION = "TestParser Downloader"

        
class Implant(Parser):
    DESCRIPTION = "TestParser Implant"
    
'''

# language=Yaml
TEST_PARSER_CONFIG = u'''
Sample:
    description: A test parser
    author: Mr. Tester
    parsers:
        - .Downloader
        - .Implant
'''


@pytest.fixture
def make_sample_parser(tmpdir):
    """
    Creates and returns a function to generate a sample parser with the
    given name as the directory (this allows us to make multiple directories if desired.)
    """

    def _make_sample_parser(
            source_name="acme",
            parser_name="Sample",
            parser_code=TEST_PARSER,
            config_text=TEST_PARSER_CONFIG
    ):
        directory = tmpdir / source_name
        directory.mkdir()

        parser_file = directory / f"{parser_name}.py"
        parser_file.write_text(parser_code, 'utf8')

        # Parser directories must have an __init__.py
        init = directory / '__init__.py'
        init.write_text(u'', 'utf8')

        config_file = directory / 'parser_config.yml'
        config_file.write_text(config_text, 'utf8')

        return parser_file, config_file

    return _make_sample_parser


@pytest.fixture
def report():
    """
    Creates dummy report for testing.
    """
    import logging
    logger = logging.getLogger("test_report")
    logging.root.setLevel(logging.DEBUG)
    input_file = mwcp.FileObject(b"some data", file_path="C:/input_file.bin")
    return mwcp.Report(input_file, "FooParser")
