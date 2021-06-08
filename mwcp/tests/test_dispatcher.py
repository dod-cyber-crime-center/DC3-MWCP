"""Tests the Dispatcher and FileObject functionality."""

import os
import pathlib

import pytest

import mwcp
from mwcp import metadata


@pytest.fixture
def components():
    """
    Setup for testing some of the dispatcher components.
    (Set it as a fixture so we can reuse the variables without having to remake)
    """
    file_A = mwcp.FileObject(b'This is file A', file_name='A_match.txt', output_file=False)
    file_B = mwcp.FileObject(b'This is file B', file_name='B_match.txt', output_file=False)
    file_C = mwcp.FileObject(b'This is file C', file_name='no_match.txt', output_file=False)

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

    dispatcher = mwcp.Dispatcher('my_dispatcher', 'acme', parsers=[A, B])

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

    # sanity check
    for file in ('file_A', 'file_B', 'file_C'):
        assert components[file].description is None

    dispatcher.parse(input_file, mwcp.Report(input_file))

    # make sure the correct files have been identified.
    for file, description in sorted(expected.items()):
        assert components[file].description == description


def test_file_object(tmpdir):
    """Tests the mwcp.FileObject class"""
    runner = mwcp.Runner(temp_directory=str(tmpdir), output_directory=str(tmpdir))
    file_object = mwcp.FileObject(b'This is some test data!')

    assert file_object.name == u'fb843efb2ffec987db12e72ca75c9ea2.bin'
    assert file_object.data == b'This is some test data!'
    assert file_object.md5 == u'fb843efb2ffec987db12e72ca75c9ea2'
    assert file_object.resources is None
    assert file_object.pe is None

    # Test temporary path.
    with file_object.temp_path() as file_path:
        file_path = pathlib.Path(file_path)
        assert file_path.exists()
        assert file_path.read_bytes() == b"This is some test data!"
    assert not file_path.exists()  # ensure cleanup

    # Test use as stream.
    with file_object.open() as fo:
        assert fo.read() == b'This is some test data!'

    # Test we can write out file object's into report.
    # TODO: This may be more appropriate for this test to be in test_report.py ?
    report = mwcp.Report(output_directory=str(tmpdir))
    with report:
        report.add(metadata.ResidualFile.from_file_object(file_object))

    assert (tmpdir / 'fb843_fb843efb2ffec987db12e72ca75c9ea2.bin').exists()
    # Legacy
    assert report.metadata['outputfile'] == [
        [file_object.file_name, '', 'fb843efb2ffec987db12e72ca75c9ea2']
    ]
    # New method.
    residual_files = report.get(metadata.ResidualFile)
    assert len(residual_files) == 1
    assert residual_files[0].name == file_object.name
    assert residual_files[0].md5 == "fb843efb2ffec987db12e72ca75c9ea2"

