"""Tests the Dispatcher and FileObject functionality."""
import logging
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
    file_D = mwcp.FileObject(b'This is file D', file_name='D_match.txt', output_file=False)

    class A(mwcp.Parser):
        DESCRIPTION = 'A Component'
        TAGS = ("tag_a", "SuperMalware")

        @classmethod
        def identify(cls, file_object):
            return file_object.name == 'A_match.txt'

        def run(self):
            self.dispatcher.add(file_B)
            self.dispatcher.add(file_C)

    class B(mwcp.Parser):
        DESCRIPTION = 'B Component'
        @classmethod
        def identify(cls, file_object):
            return file_object.name == 'B_match.txt'

    class D(mwcp.Parser):
        DESCRIPTION = 'D Component'
        @classmethod
        def identify(cls, file_object):
            return file_object.name == 'D_match.txt', {"some other": "content"}

    dispatcher = mwcp.Dispatcher('my_dispatcher', 'acme', parsers=[A, B, D])

    return locals()


def test_identify_file(components):
    """Tests the _identify_file"""
    dispatcher = components['dispatcher']
    assert list(dispatcher._identify_parsers(components['file_A'])) == [(components['A'], tuple())]
    assert list(dispatcher._identify_parsers(components['file_B'])) == [(components['B'], tuple())]
    assert list(dispatcher._identify_parsers(components['file_C'])) == []
    assert list(dispatcher._identify_parsers(components['file_D'])) == [
        (components['D'], ({"some other": "content"},))
    ]


@pytest.mark.parametrize("input_file,expected", [
    ('file_A', {'file_A': 'A Component', 'file_B': 'B Component', 'file_C': 'Unidentified file', 'file_D': None}),
    ('file_B', {'file_A': None, 'file_B': 'B Component', 'file_C': None, 'file_D': None}),
    ('file_C', {'file_A': None, 'file_B': None, 'file_C': 'Unidentified file', 'file_D': None}),
    ('file_D', {'file_A': None, 'file_B': None, 'file_C': None, 'file_D': 'D Component'})
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


def test_tagging(components):
    """Tests tags gets added from Parser class."""
    dispatcher = components['dispatcher']
    input_file = components['file_A']

    assert not input_file.tags
    dispatcher.parse(input_file, mwcp.Report(input_file))
    assert input_file.tags == {"tag_a", "SuperMalware"}


@pytest.mark.xfail(reason="File Recursion detection temporarily disabled.")
def test_recursion_handling(tmpdir):
    """Tests handling of avoiding a recursive loop"""
    file_A = mwcp.FileObject(b'This is file A', file_name='A_match.txt', output_file=False)
    file_A2 = mwcp.FileObject(b'This is file A2', file_name='A_match.txt', output_file=False)
    file_B = mwcp.FileObject(b'This is file B', file_name='B_match.txt', output_file=False)

    class A(mwcp.Parser):
        DESCRIPTION = 'A Component'

        seen_A = False
        seen_A2 = False

        @classmethod
        def identify(cls, file_object):
            return file_object.name == 'A_match.txt'

        def run(self):
            # If we get run with the same file twice we fail.
            if self.file_object == file_A:
                if A.seen_A:
                    pytest.fail("Processed file_A twice!")
                A.seen_A = True
            if self.file_object == file_A2:
                if A.seen_A2:
                    pytest.fail("Processed file_A2 twice!")
                A.seen_A2 = True

            self.dispatcher.add(file_B)
            self.dispatcher.add(file_A2)  # would cause a recursive loop.
            # Also ensure it works with the same file, but new object instance.
            self.dispatcher.add(mwcp.FileObject(b'This is file A', file_name='A_match.txt', output_file=False))

    class B(mwcp.Parser):
        DESCRIPTION = 'B Component'
        @classmethod
        def identify(cls, file_object):
            return file_object.name == 'B_match.txt'

        def run(self):
            self.dispatcher.add(file_A)

    dispatcher = mwcp.Dispatcher('my_dispatcher', 'acme', parsers=[A, B])

    # Test recursion in own parser.
    report = mwcp.Report(file_A, include_logs=True)
    with report:
        dispatcher.parse(file_A, report)
    assert not report.errors

    # Test recursion in another parser.
    A.seen_A = False
    A.seen_A2 = False
    report = mwcp.Report(file_B, include_logs=True)
    with report:
        dispatcher.parse(file_B, report)
    assert not report.errors


def test_file_object(tmpdir):
    """Tests the mwcp.FileObject class"""
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
        report.add(metadata.File.from_file_object(file_object))

    assert (tmpdir / 'fb843_fb843efb2ffec987db12e72ca75c9ea2.bin').exists()
    # Legacy
    assert report.metadata['outputfile'] == [
        [file_object.name, '', 'fb843efb2ffec987db12e72ca75c9ea2']
    ]
    # New method.
    residual_files = report.get(metadata.File)
    assert len(residual_files) == 1
    assert residual_files[0].name == file_object.name
    assert residual_files[0].md5 == "fb843efb2ffec987db12e72ca75c9ea2"
