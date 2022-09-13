"""
Tests mwcp.metadata elements.
"""
import json
import logging
import pathlib
import textwrap

import pytest

import mwcp
from mwcp import metadata


def test_tags():
    p = metadata.Path2("C:\\hello\\world.txt")

    # test single
    assert p.add_tag("download") is p
    assert p.tags == ["download"]

    # test multiple
    assert p.add_tag("download", "APT9000", "text document") is p
    assert p.tags == ["APT9000", "download", "text document"]


def test_serialization():
    # Test simple metadata.
    p = metadata.Path2("C:\\hello\\world.txt").add_tag("download")
    p_dict = p.as_dict()
    assert p_dict == {
        'type': 'path',
        'tags': ['download'],
        'path': r"C:\hello\world.txt",
        'posix': False,
        'is_dir': None,
        'file_system': None,
    }
    # language=json
    assert p.as_json() == textwrap.dedent(r"""
        {
            "type": "path",
            "tags": [
                "download"
            ],
            "path": "C:\\hello\\world.txt",
            "is_dir": null,
            "posix": false,
            "file_system": null
        }
    """).strip()
    assert metadata.Path2.from_dict(p_dict) == p
    assert metadata.Metadata.from_dict(p_dict) == p

    # Test nested metadata.
    u = metadata.URL("http://google.com")
    u_dict = u.as_dict()
    assert u_dict == {
        'type': 'url',
        'tags': [],
        'url': 'http://google.com',
        'application_protocol': 'http',
        'credential': None,
        'path': None,
        'query': '',
        'socket': {
            'type': 'socket',
            'tags': [],
            'address': 'google.com',
            'c2': None,
            'listen': None,
            'network_protocol': None,
            'port': None
        },
      }
    # language=json
    assert u.as_json() == textwrap.dedent(r"""
        {
            "type": "url",
            "tags": [],
            "url": "http://google.com",
            "socket": {
                "type": "socket",
                "tags": [],
                "address": "google.com",
                "port": null,
                "network_protocol": null,
                "c2": null,
                "listen": null
            },
            "path": null,
            "query": "",
            "application_protocol": "http",
            "credential": null
        }
    """).strip()
    assert metadata.URL.from_dict(u_dict) == u
    assert metadata.Metadata.from_dict(u_dict) == u


def test_schema(tmp_path):
    """
    Tests schema generation to ensure schema.json is up to date.
    """
    schema_json = pathlib.Path(mwcp.__file__).parent / "config" / "schema.json"
    with schema_json.open("r") as fo:
        schema = json.load(fo)
    assert mwcp.schema() == schema, "Schema out of date. Run mwcp/tools/update_schema.py"


def test_schema_validation(report, metadata_items):
    pytest.importorskip("jsonschema")
    import jsonschema

    logger = logging.getLogger(__name__)

    with report:
        for item in metadata_items:
            jsonschema.validate(item.as_json_dict(), item.schema())
            report.add(item)

        # Add some log messages in for good measure.
        logger.info("Test info log")
        logger.error("Test error log")
        logger.debug("Test debug log")

    jsonschema.validate(report.as_json_dict(), mwcp.schema())


def test_path_alternative_constructors():
    """
    Tests alternative constructors for path.
    """
    path = metadata.Path2.from_segments("C:", "hello", "world.txt")
    assert path.path == "C:\\hello\\world.txt"
    path = metadata.Path2.from_segments("C:", "hello", "world.txt", posix=True)
    assert path.path == "C:/hello/world.txt"
    path = metadata.Path2.from_segments("world.txt")
    assert path.path == "world.txt"
    assert path.posix is False

    path = metadata.Path2.from_pathlib_path(pathlib.PureWindowsPath("C:\\hello\\world.txt"))
    assert path.path == "C:\\hello\\world.txt"
    assert path.posix is False
    path = metadata.Path2.from_pathlib_path(pathlib.PurePosixPath("/home/user/test.txt"))
    assert path.path == "/home/user/test.txt"
    assert path.posix is True


def test_path_absolute_segment_issue():
    """
    Tests issue with absolute path causing previous segments being excluded in Path2.from_segments()
    """
    assert metadata.Path2.from_segments("hello", "\\world").path == r"hello\world"
    assert metadata.Path2.from_segments("\\hello", "\\world").path == r"\hello\world"
    assert metadata.Path2.from_segments("C:\\hello", "\\world").path == r"C:\hello\world"
    assert metadata.Path2.from_segments("hello", "\\world", posix=True).path == r"hello/\world"
    assert metadata.Path2.from_segments("hello", "/\\world", posix=True).path == r"hello/\world"
    assert metadata.Path2.from_segments("/hello", "/world", posix=True).path == r"/hello/world"
