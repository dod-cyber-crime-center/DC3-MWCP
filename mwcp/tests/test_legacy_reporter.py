# coding=utf-8
"""
Tests the legacy features of mwcp.Reporter object.

These features are now replaced by test_report.py and test_runner.py
"""

import os

import pytest

import mwcp


@pytest.mark.parametrize('key,value,expected', [
    ('filepath', br'C:\dir\file.txt', {
        'filepath': [r'C:\dir\file.txt'],
        'filename': ['file.txt'],
        'directory': [r'C:\dir']
    }),
    ('servicedll', br'C:\Windows\Temp\1.tmp', {
        'servicedll': [r'C:\Windows\Temp\1.tmp'],
        'filepath': [r'C:\Windows\Temp\1.tmp'],
        'filename': ['1.tmp'],
        'directory': [r'C:\Windows\Temp']
    }),
    ('c2_url', b'http://[fe80::20c:1234:5678:9abc]:80/badness', {
        'c2_url': ['http://[fe80::20c:1234:5678:9abc]:80/badness'],
        'url': ['http://[fe80::20c:1234:5678:9abc]:80/badness'],
        'urlpath': ['/badness'],
        'c2_socketaddress': [['fe80::20c:1234:5678:9abc', '80', '']],
        'socketaddress': [['fe80::20c:1234:5678:9abc', '80', '']],
        'c2_address': ['fe80::20c:1234:5678:9abc'],
        'address': ['fe80::20c:1234:5678:9abc'],
        'port': [['80', '']]
    }),
    ('url', b'http://127.0.0.1/really/bad?hostname=pwned', {
        'url': ['http://127.0.0.1/really/bad?hostname=pwned'],
        'urlpath': ['/really/bad'],
        'address': ['127.0.0.1']
    }),
    ('proxy', (b'admin', b'pass', b'192.168.1.1', b'80', 'tcp'), {
        'proxy': [['admin', 'pass', '192.168.1.1', '80', 'tcp']],
        'proxy_socketaddress': [['192.168.1.1', '80', 'tcp']],
        'socketaddress': [['192.168.1.1', '80', 'tcp']],
        'proxy_address': ['192.168.1.1'],
        'address': ['192.168.1.1'],
        'port': [['80', 'tcp']],
        'credential': [['admin', 'pass']],
        'password': ['pass'],
        'username': ['admin']
    }),
    ('rsa_private_key', ('0x7', '0xbb', '0x17', '0x11', '0xb', '0x7', '0x3', '0xe'), {
        'rsa_private_key': [['0x7', '0xbb', '0x17', '0x11', '0xb', '0x7', '0x3', '0xe']]
    }),
    # Test auto padding.
    ('rsa_private_key', ('0x7', '0xbb', '0x17', '0x11', '0xb'), {
        'rsa_private_key': [['0x7', '0xbb', '0x17', '0x11', '0xb', '', '', '']]
    }),
    ('other', {b'foo': b'bar', 'biz': 'baz'}, {
        'other': {
            'foo': 'bar',
            'biz': 'baz'
        }
    })
])
def test_add_metadata(key, value, expected):
    report = mwcp.Report()
    with report:
        report.add_metadata(key, value)
    assert report.metadata == expected


def test_other_add_metadata():
    """Tests that adding multiple 'other' keys of same will convert to a list."""
    report = mwcp.Report()
    with report:
        report.add_metadata('other', {b'foo': b'bar', 'biz': 'baz'})
        assert report.metadata == {'other': {'foo': 'bar', 'biz': 'baz'}}
        report.add_metadata('other', {b'foo': b'boop'})
        assert report.metadata == {'other': {'foo': ['bar', 'boop'], 'biz': 'baz'}}


def test_output_file(tmpdir):
    test_file = tmpdir / '9c91e_foo.txt'
    report = mwcp.Report(output_directory=str(tmpdir))
    with report:
        assert report.output_file(b'This is data!', 'foo.txt', description='A foo file') == str(test_file)

        assert test_file.exists()
        assert test_file.read_binary() == b'This is data!'
        assert report.metadata['outputfile'] == [
            ['foo.txt', 'A foo file', '9c91e665b5b7ba5a3066c92dd02d3d7c']
        ]

        # Add file with same name to test name collision code.
        test_file = tmpdir / '4d8cf_foo.txt'
        assert report.output_file(b'More data!', 'foo.txt', description='Another foo file') == str(test_file)

        assert test_file.exists()
        assert test_file.read_binary() == b'More data!'
        assert report.metadata['outputfile'] == [
            ['foo.txt', 'A foo file', '9c91e665b5b7ba5a3066c92dd02d3d7c'],
            ['foo.txt', 'Another foo file', '4d8cfa4b19f5f971b0e6d79250cb1321'],
        ]

    # Test file sanitization
    test_file = tmpdir / '6f1ed_hello.txt'
    report = mwcp.Report(output_directory=str(tmpdir))
    with report:
        assert report.output_file(b'blah', u'héllo!!\x08.txt') == str(test_file)

        assert test_file.exists()
        assert test_file.read_binary() == b'blah'
        assert report.metadata['outputfile'] == [
            [u'héllo!!\x08.txt', '', '6f1ed002ab5595859014ebf0951522d9']
        ]


def test_print_report(datadir):
    """Tests the text report generation."""
    report = mwcp.Report()
    with report:
        report.add_metadata('proxy', (b'admin', b'pass', b'192.168.1.1', b'80', 'tcp'))
        report.add_metadata('other', {b'foo': 'bar', 'biz': b'baz\x00\x01'})
        report.output_file(b'data', 'file_1.exe', 'example output file')

    print(report.as_text())
    assert report.as_text() == (datadir / "report.txt").read_text()


# TODO: Deal with field ordering?
# def test_standard_field_order():
#     """Tests that STANDARD_FIELD_ORDER is updated to the field.json file."""
#     with open(mwcp.config.get("FIELDS_PATH"), "rb") as f:
#         fields = json.load(f)
#
#     ignore_fields = INFO_FIELD_ORDER + ["debug", "other", "outputfile"]
#
#     assert sorted(STANDARD_FIELD_ORDER) == sorted(set(fields.keys()) - set(ignore_fields))
