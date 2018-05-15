"""Tests the mwcp.Reporter object."""

from __future__ import unicode_literals

import os

import pytest

import mwcp


def test_managed_tempdir(tmpdir):
    reporter = mwcp.Reporter(tempdir=str(tmpdir))
    managed_tempdir = reporter.managed_tempdir()
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

    # Print out the debug messages to make a more useful message if we fail.
    debug = reporter.metadata.get('debug', None)
    if debug:
        print('\n'.join(debug))
        del reporter.metadata['debug']

    # We shouldn't have any error messages. If we do that means an exception has occurred.
    # Lets raise that exception to create a more useful message.
    errors = reporter.errors
    if errors:
        raise AssertionError('\n'.join(errors))

    assert reporter.metadata == expected


def test_other_add_metadata():
    """Tests that adding multiple 'other' keys of same will convert to a list."""
    reporter = mwcp.Reporter()
    reporter.add_metadata('other', {b'foo': b'bar', 'biz': 'baz'})
    assert reporter.metadata == {'other': {'foo': 'bar', 'biz': 'baz'}}
    reporter.add_metadata('other', {b'foo': b'boop'})
    assert reporter.metadata == {'other': {'foo': ['bar', 'boop'], 'biz': 'baz'}}


def test_output_file(tmpdir):
    output_dir = str(tmpdir)
    reporter = mwcp.Reporter(outputdir=output_dir)
    reporter.output_file(b'This is data!', 'foo.txt', description='A foo file')

    file_path = os.path.join(output_dir, 'foo.txt')
    assert os.path.exists(file_path)
    with open(file_path, 'rb') as fo:
        assert fo.read() == b'This is data!'
    assert reporter.outputfiles['foo.txt'] == {
        'data': b'This is data!',
        'description': 'A foo file',
        'md5': '9c91e665b5b7ba5a3066c92dd02d3d7c',
        'path': file_path
    }
    assert reporter.metadata['outputfile'] == [['foo.txt', 'A foo file', '9c91e665b5b7ba5a3066c92dd02d3d7c']]

