import pytest


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
def Sample_parser(tmpdir):
    """Creates and returns the file path to a test parser."""
    parser_file = tmpdir / 'Sample.py'
    parser_file.write_text(TEST_PARSER, 'utf8')

    # Parser directories must have an __init__.py
    init = tmpdir / '__init__.py'
    init.write_text(u'', 'utf8')

    config_file = tmpdir / 'parser_config.yml'
    config_file.write_text(TEST_PARSER_CONFIG, 'utf8')

    return parser_file, config_file
