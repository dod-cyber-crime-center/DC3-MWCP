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
    p = metadata.Path("C:\\hello\\world.txt")

    # test single
    assert p.add_tag("download") is p
    assert p.tags == ["download"]

    # test multiple
    assert p.add_tag("download", "APT9000", "text document") is p
    assert p.tags == ["APT9000", "download", "text document"]


def test_serialization():
    # Test simple metadata.
    p = metadata.Path("C:\\hello\\world.txt").add_tag("download")
    p_dict = p.as_dict()
    assert p_dict == {
        'type': 'path',
        'tags': ['download'],
        'path': 'C:\\hello\\world.txt',
        'directory_path': 'C:\\hello',
        'name': 'world.txt',
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
            "directory_path": "C:\\hello",
            "name": "world.txt",
            "is_dir": null,
            "file_system": null
        }
    """).strip()
    assert metadata.Path.from_dict(p_dict) == p
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


def test_schema_validation(report):
    pytest.importorskip("jsonschema")
    import jsonschema

    logger = logging.getLogger(__name__)

    # Create a report (validating each element along the way),
    # then validate the report in its entirety.
    items = [
        metadata.Path("C:\\windows\\temp\\1\\log\\keydb.txt", is_dir=False),
        metadata.Directory("%APPDATA%\\foo"),
        metadata.Base16Alphabet("0123456789ABCDEF"),
        metadata.Base32Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="),
        metadata.Base64Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
        metadata.Credential(username="admin", password="123456"),
        metadata.Socket(address="bad.com", port=21, network_protocol="tcp"),
        metadata.URL("https://10.11.10.13:443/images/baner.jpg"),
        metadata.Proxy(
            username="admin",
            password="pass",
            address="192.168.1.1",
            port=80,
            protocol="tcp",
        ),
        metadata.FTP(
            username="admin",
            password="pass",
            url="ftp://badhost.com:21",
        ),
        metadata.EmailAddress("email@bad.com"),
        metadata.Event("MicrosoftExist"),
        metadata.UUID("654e5cff-817c-4e3d-8b01-47a6f45ae09a"),
        metadata.InjectionProcess("svchost"),
        metadata.Interval(3),
        metadata.EncryptionKey(b"myrc4key", algorithm="rc4"),
        metadata.MissionID("target4"),
        metadata.Mutex("ithinkimalonenow"),
        metadata.Other(key="keylogger", value="True"),
        metadata.Pipe("\\.\\pipe\\namedpipe"),
        metadata.Registry(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            data="c:\\update.exe",
        ),
        metadata.RSAPrivateKey(
            public_exponent=0x07,
            modulus=0xbb,
            private_exponent=0x17,
            p=0x11,
            q=0x0b,
            d_mod_p1=0x07,
            d_mod_q1=0x03,
            q_inv_mod_p=0x0e,
        ),
        metadata.RSAPublicKey(
            public_exponent=0x07,
            modulus=0xbb,
        ),
        metadata.Service(
            name="WindowsUserManagement",
            display_name="Windows User Management",
            description="Provides a common management to access information about windows user.",
            image="%System%\\svohost.exe",
        ),
        metadata.UserAgent("Mozilla/4.0 (compatible; MISE 6.0; Windows NT 5.2)"),
        metadata.Version("3.1"),
        metadata.File(
            name="config.xml",
            description="Extracted backdoor Foo config file",
            data=b"foo = bar"
        ),
    ]

    with report:
        for item in items:
            jsonschema.validate(item.as_json_dict(), item.schema())
            report.add(item)

        # Add some log messages in for good measure.
        logger.info("Test info log")
        logger.error("Test error log")
        logger.debug("Test debug log")


    jsonschema.validate(report.as_json_dict(), mwcp.schema())
