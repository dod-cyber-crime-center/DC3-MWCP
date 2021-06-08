"""
Tests mwcp.metadata elements.
"""
import textwrap

from mwcp import metadata


def test_tags():
    p = metadata.Path("C:\\hello\\world.txt")

    # test single
    assert p.add_tag("download") is p
    assert p.tags == {"download"}

    # test multiple
    assert p.add_tag("download", "APT9000", "text document") is p
    assert p.tags == {"download", "APT9000", "text document"}


def test_serialization():
    # Test simple metadata.
    p = metadata.Path("C:\\hello\\world.txt").add_tag("download")
    p_dict = p.as_dict()
    assert p_dict == {
        'type': 'path',
        'tags': {'download'},
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
    assert metadata.Element.from_dict(p_dict) == p

    # Test nested metadata.
    u = metadata.URL("http://google.com")
    u_dict = u.as_dict()
    assert u_dict == {
        'type': 'url',
        'tags': set(),
        'url': 'http://google.com',
        'application_protocol': 'http',
        'credential': None,
        'path': None,
        'query': '',
        'socket': {
            'type': 'socket',
            'tags': set(),
            'address': 'google.com',
            'c2': None,
            'listen': None,
            'network_protocol': 'tcp',
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
                "network_protocol": "tcp",
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
    assert metadata.Element.from_dict(u_dict) == u
