"""Tests the Dispatcher and FileObject functionality."""

import codecs
import os

import pytest

import mwcp


@pytest.fixture
def components():
    """
    Setup for testing some of the dispatcher components.
    (Set it as a fixture so we can reuse the variables without having to remake)
    """
    reporter = mwcp.Reporter()
    file_A = mwcp.FileObject(b'This is file A', reporter, file_name='A_match.txt', output_file=False)
    file_B = mwcp.FileObject(b'This is file B', reporter, file_name='B_match.txt', output_file=False)
    file_C = mwcp.FileObject(b'This is file C', reporter, file_name='no_match.txt', output_file=False)

    class A(mwcp.Parser):
        DESCRIPTION = 'A Component'
        @classmethod
        def identify(cls, file_object):
            return file_object.file_name == 'A_match.txt'

        def run(self):
            self.dispatcher.add_to_queue(file_B)
            self.dispatcher.add_to_queue(file_C)

    class B(mwcp.Parser):
        DESCRIPTION = 'B Component'
        @classmethod
        def identify(cls, file_object):
            return file_object.file_name == 'B_match.txt'

    dispatcher = mwcp.Dispatcher('my_dispatcher', parsers=[A, B])

    return locals()


def test_identify_file(components):
    """Tests the _identify_file"""
    dispatcher = components['dispatcher']
    assert list(dispatcher._iter_parsers(components['file_A'])) == [components['A']]
    assert list(dispatcher._iter_parsers(components['file_B'])) == [components['B']]
    assert list(dispatcher._iter_parsers(components['file_C'])) == []


@pytest.mark.parametrize("input_file,expected", [
    ('file_A', {'file_A': 'A Component', 'file_B': 'B Component', 'file_C': 'Unidentified file'}),
    ('file_B', {'file_A': None, 'file_B': 'B Component', 'file_C': None}),
    ('file_C', {'file_A': None, 'file_B': None, 'file_C': 'Unidentified file'}),
])
def test_dispatch(components, input_file, expected):
    """Test dispatching files."""
    dispatcher = components['dispatcher']
    input_file = components[input_file]
    reporter = components['reporter']

    # sanity check
    for file in ('file_A', 'file_B', 'file_C'):
        assert components[file].description is None

    dispatcher.parse(input_file, reporter)

    # make sure the correct files have been identified.
    for file, description in sorted(expected.items()):
        assert components[file].description == description


def test_file_object(tmpdir):
    """Tests the mwcp.FileObject class"""
    output_dir = str(tmpdir)
    reporter = mwcp.Reporter(tempdir=output_dir, outputdir=output_dir)
    file_object = mwcp.FileObject(b'This is some test data!', reporter)

    assert file_object.file_name == u'fb843efb2ffec987db12e72ca75c9ea2.bin'
    assert file_object.file_data == b'This is some test data!'
    assert file_object.md5 == u'fb843efb2ffec987db12e72ca75c9ea2'
    assert file_object.resources is None
    assert file_object.pe is None
    assert file_object.file_path.startswith(os.path.join(output_dir, 'mwcp-managed_tempdir-'))

    with file_object as fo:
        assert fo.read() == b'This is some test data!'

    assert not reporter.outputfiles
    file_object.output()
    file_path = os.path.join(output_dir, 'fb843efb2ffec987db12e72ca75c9ea2.bin')
    assert file_object.file_name in reporter.outputfiles
    assert reporter.outputfiles[file_object.file_name] == {
        'data': b'This is some test data!',
        'path': file_path,
        'description': '',
        'md5': 'fb843efb2ffec987db12e72ca75c9ea2'
    }
    assert os.path.exists(file_path)
