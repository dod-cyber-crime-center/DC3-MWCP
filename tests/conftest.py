
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

class TestParser(Parser):
    def __init__(self, reporter):
        Parser.__init__(self, description="A test parser", author="Mr. Tester", reporter=reporter)

    def run(self):
        pass
'''


@pytest.fixture
def test_parser(tmpdir):
    """Creates and returns the file path to a test parser."""
    file_path = os.path.join(str(tmpdir), 'test_parser.py')
    with open(file_path, 'w') as f:
        f.write(TEST_PARSER)
    return file_path
