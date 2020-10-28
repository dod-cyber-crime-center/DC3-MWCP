# coding=utf-8
"""Tests the mwcp.Reporter object."""

import os
import json

import pytest

import mwcp
from mwcp.reporter import STANDARD_FIELD_ORDER, INFO_FIELD_ORDER


def test_managed_tempdir(tmpdir):
    reporter = mwcp.Reporter(tempdir=str(tmpdir))
    managed_tempdir = reporter.managed_tempdir
    assert os.path.exists(managed_tempdir)
    assert managed_tempdir.startswith(os.path.join(str(tmpdir), 'mwcp-managed_tempdir-'))


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
        'c2_socketaddress': [['fe80::20c:1234:5678:9abc', '80', 'tcp']],
        'socketaddress': [['fe80::20c:1234:5678:9abc', '80', 'tcp']],
        'c2_address': ['fe80::20c:1234:5678:9abc'],
        'address': ['fe80::20c:1234:5678:9abc'],
        'port': [['80', 'tcp']]
    }),
    ('url', b'ftp://127.0.0.1/really/bad?hostname=pwned', {
        'url': ['ftp://127.0.0.1/really/bad?hostname=pwned'],
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
    ('rsa_private_key', ('0x07', '0xbb', '0x17', '0x11', '0x0b', '0x07', '0x03', '0x0e'), {
        'rsa_private_key': [['0x07', '0xbb', '0x17', '0x11', '0x0b', '0x07', '0x03', '0x0e']]
    }),
    # Test auto padding.
    ('rsa_private_key', ('0x07', '0xbb', '0x17', '0x11', '0x0b'), {
        'rsa_private_key': [['0x07', '0xbb', '0x17', '0x11', '0x0b', '', '', '']]
    }),
    ('other', {b'foo': b'bar', 'biz': 'baz'}, {
        'other': {
            'foo': 'bar',
            'biz': 'baz'
        }
    })
])
def test_add_metadata(key, value, expected):
    reporter = mwcp.Reporter()
    reporter.add_metadata(key, value)
    assert reporter.metadata == expected


def test_other_add_metadata():
    """Tests that adding multiple 'other' keys of same will convert to a list."""
    reporter = mwcp.Reporter()
    reporter.add_metadata('other', {b'foo': b'bar', 'biz': 'baz'})
    assert reporter.metadata == {'other': {'foo': 'bar', 'biz': 'baz'}}
    reporter.add_metadata('other', {b'foo': b'boop'})
    assert reporter.metadata == {'other': {'foo': ['bar', 'boop'], 'biz': 'baz'}}


def test_output_file(tmpdir):
    test_file = tmpdir / '9c91e_foo.txt'
    reporter = mwcp.Reporter(outputdir=str(tmpdir))
    assert reporter.output_file(b'This is data!', 'foo.txt', description='A foo file') == str(test_file)

    assert test_file.exists()
    assert test_file.read_binary() == b'This is data!'
    assert reporter.metadata['outputfile'] == [
        ['foo.txt', 'A foo file', '9c91e665b5b7ba5a3066c92dd02d3d7c']
    ]

    # Add file with same name to test name collision code.
    test_file = tmpdir / '4d8cf_foo.txt'
    assert reporter.output_file(b'More data!', 'foo.txt', description='Another foo file') == str(test_file)

    assert test_file.exists()
    assert test_file.read_binary() == b'More data!'
    assert reporter.metadata['outputfile'] == [
        ['foo.txt', 'A foo file', '9c91e665b5b7ba5a3066c92dd02d3d7c'],
        ['foo.txt', 'Another foo file', '4d8cfa4b19f5f971b0e6d79250cb1321'],
    ]

    # Test file sanitization
    test_file = tmpdir / '6f1ed_hello.txt'
    reporter = mwcp.Reporter(outputdir=str(tmpdir))
    assert reporter.output_file(b'blah', u'héllo!!\x08.txt') == str(test_file)

    assert test_file.exists()
    assert test_file.read_binary() == b'blah'
    assert reporter.metadata['outputfile'] == [
        [u'héllo!!\x08.txt', '', '6f1ed002ab5595859014ebf0951522d9']
    ]


def test_print_report(tmpdir, capsys):
    """Tests the text report generation."""
    reporter = mwcp.Reporter(outputdir=str(tmpdir))
    reporter.add_metadata('proxy', (b'admin', b'pass', b'192.168.1.1', b'80', 'tcp'))
    reporter.add_metadata('other', {b'foo': b'bar', 'biz': 'baz\x00\x01'})
    reporter.output_file(b'data', 'file_1.exe', 'example output file')

    expected_output = u'''
----Standard Metadata----

proxy                admin pass 192.168.1.1 80 tcp
proxy_socketaddress  192.168.1.1:80/tcp
proxy_address        192.168.1.1
socketaddress        192.168.1.1:80/tcp
address              192.168.1.1
port                 80/tcp
credential           admin:pass
username             admin
password             pass

----Other Metadata----

biz                  baz\x00\x01
foo                  bar

----Output Files----

file_1.exe           example output file
                     8d777f385d3dfec8815d20f7496026dc
'''

    assert reporter.get_output_text() == expected_output

    reporter.print_report()
    assert capsys.readouterr().out == expected_output + u'\n'


def test_standard_field_order():
    """Tests that STANDARD_FIELD_ORDER is updated to the field.json file."""
    with open(mwcp.config.get("FIELDS_PATH"), "rb") as f:
        fields = json.load(f)

    ignore_fields = INFO_FIELD_ORDER + ["debug", "other", "outputfile"]

    assert sorted(STANDARD_FIELD_ORDER) == sorted(set(fields.keys()) - set(ignore_fields))
