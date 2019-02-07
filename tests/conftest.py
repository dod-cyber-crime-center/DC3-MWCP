
import os

import pytest


@pytest.fixture
def test_file(tmpdir):
    """Fixture for providing a test file to pass to mwcp."""
    file_path = os.path.join(str(tmpdir), 'test.txt')
    with open(file_path, 'wb') as f:
        f.write(b"This is some test data!")
    return file_path


@pytest.fixture
def test_dir(tmpdir):
    """Fixture for providing a test directory to pass to mwcp."""
    directory = os.path.join(str(tmpdir), 'test_dir')
    os.makedirs(directory)
    for i in range(5):
        file_path = os.path.join(directory, 'test_{}.txt'.format(i))
        with open(file_path, 'wb') as f:
            f.write(b"This is some test data!")
    return directory


TEST_PARSER = '''
from mwcp import Parser

class Downloader(Parser):
    DESCRIPTION = "TestParser Downloader"

        
class Implant(Parser):
    DESCRIPTION = "TestParser Implant"
    
'''

TEST_PARSER_CONFIG = '''
test_parser:
    description: A test parser
    author: Mr. Tester
    parsers:
        - .Downloader
        - .Implant
'''


@pytest.fixture
def test_parser(tmpdir):
    """Creates and returns the file path to a test parser."""
    file_path = os.path.join(str(tmpdir), 'test_parser.py')
    with open(file_path, 'w') as f:
        f.write(TEST_PARSER)

    # Parser directories must have an __init__.py
    with open(os.path.join(str(tmpdir), '__init__.py'), 'w') as _:
        pass
        
    config_path = os.path.join(str(tmpdir), 'parser_config.yml')
    with open(config_path, 'w') as f:
        f.write(TEST_PARSER_CONFIG)
        
    return file_path, config_path
