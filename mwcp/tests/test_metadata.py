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
    # It should also work without the "type" field if using Path2 directly.
    p_dict.pop("type")
    assert metadata.Path2.from_dict(p_dict) == p

    # Test nested metadata.
    u = metadata.URL("http://google.com")
    u_dict = u.as_dict()
    assert u_dict == {
        'type': 'url',
        'tags': [],
        'url': 'http://google.com',
        'protocol': 'http',
        'path': None,
        'query': None,
      }
    # language=json
    assert u.as_json() == textwrap.dedent(r"""
        {
            "type": "url",
            "tags": [],
            "url": "http://google.com",
            "path": null,
            "query": null,
            "protocol": "http"
        }
    """).strip()
    assert metadata.URL2.from_dict(u_dict) == u
    assert metadata.Metadata.from_dict(u_dict) == u


def test_other_serialization_issue():
    """
    Tests issue from deserializing a metadata.Other component, due to the extra "value_format" field.
    """
    other = metadata.Other("test", b"hello")
    other_dict = other.as_dict()
    assert other_dict == {
        "type": "other",
        "tags": [],
        "key": "test",
        "value": b"hello",
        "value_format": "bytes",
    }
    assert metadata.Other.from_dict(other_dict) == other
    # Should also work if data is still encoded.
    assert metadata.Other.from_dict({"key": "test", "value": "aGVsbG8=", "value_format": "bytes"}) == other


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


@pytest.mark.parametrize("key,encoding,display", [
    (b"hello", "ascii", '0x68656c6c6f ("hello")'),
    (b"ab16", "ascii", '0x61623136 ("ab16")'),
    (b"\xde\xad\xbe\xef", None, '0xdeadbeef'),
    (b"\xe60\xfc0\xb60\xfc0%R\xb50\xa40\xc80", "utf-16-le", '0xe630fc30b630fc302552b530a430c830 ("ユーザー別サイト")'),
])
def test_encryption_key_detect_encoding(key, encoding, display):
    """
    Tests displaying of encryption key in report.
    """
    key = metadata.EncryptionKey(key)
    assert key._detect_encoding() == encoding
    assert key.as_formatted_dict()["key"] == display


@pytest.mark.parametrize("key,encoding,display", [
    (b"hello", "ascii", '0x68656c6c6f ("hello")'),
    (b"hello", None, '0x68656c6c6f'),
    (b"\xde\xad\xbe\xef", None, '0xdeadbeef'),
    (b"\xde\xad\xbe\xef", "latin1", '0xdeadbeef ("Þ\xad¾ï")'),
])
def test_encryption_key_with_encoding(key, encoding, display):
    """
    Tests EncryptionKey.with_encoding()
    """
    key = metadata.EncryptionKey(key).with_encoding(encoding)
    assert key.as_formatted_dict()["key"] == display


def test_scheduled_task_from_xml():
    """
    Tests ScheduledTask.from_xml()
    """
    # language=xml
    scheduled_task = metadata.ScheduledTask.from_xml(r"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
            <RegistrationInfo>
                <Date>2005-10-11T13:21:17-08:00</Date>
                <Author>AuthorName</Author>
                <Version>1.0.0</Version>
                <Description>Task starts after a specified time.</Description>
            </RegistrationInfo>
            <Triggers>
                <TimeTrigger>
                    <StartBoundary>2023-07-13T13:14:41.816836</StartBoundary>
                    <Enabled>true</Enabled>
                    <Repetition>
                        <Interval>PT1M</Interval>
                    </Repetition>
                </TimeTrigger>
            </Triggers>
            <Actions Context="Author">
                <Exec>
                    <Command>C:\Windows\System32\replace.exe</Command>
                    <Arguments>"C:\Users\bob\implant.exe" C:\Windows\Temp /A</Arguments>
                </Exec>
                <Exec>
                    <Command>C:\Windows\Temp\implant.exe</Command>
                </Exec>
            </Actions>
        </Task>
    """)
    assert scheduled_task.as_dict() == {
        "type": "scheduled_task",
        "tags": [],
        "name": None,
        "author": "AuthorName",
        "description": "Task starts after a specified time.",
        "credentials": None,
        "actions": [
            {
                "type": "command",
                "tags": [],
                "value": 'C:\\Windows\\System32\\replace.exe "C:\\Users\\bob\\implant.exe" C:\\Windows\\Temp /A',
                "cwd": None,
            },
            {
                "type": "command",
                "tags": [],
                "value": 'C:\\Windows\\Temp\\implant.exe',
                "cwd": None,
            }
        ]
    }
