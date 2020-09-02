"""Tests our construct helpers."""

import doctest
import os
import sys

import pytest

from mwcp.utils import construct


@pytest.mark.xfail(
    raises=ValueError,
    reason="Doctest is producing a 'wrapper loop when unwrapping obj_' error"
)
def test_helpers():
    """Tests that the doctests for the helpers work."""
    helper_modules = [
        construct.helpers,
        construct.datetime_,
        construct.network,
        construct.windows_enums,
        construct.windows_structures
    ]
    for module in helper_modules:
        results = doctest.testmod(module)
        assert not results.failed


def test_html():
    """Tests the html construct."""
    # Test doctests
    results = doctest.testmod(construct.construct_html)
    assert not results.failed

    # Test with an example
    EMBED_SPEC = construct.Struct(
        'a' / construct.IP4Address,
        'b' / construct.IP4Address,
        'c' / construct.IP4Address,
        'd' / construct.IP4Address
    )

    address_struct = construct.Struct(
        'first' / construct.Struct('a' / construct.Byte, 'b' / construct.Byte),
        'second' / construct.Struct('inner2' / construct.Bytes(2))
        # 'internal' / IP4Address
    )

    PACKET = construct.Struct(
        construct.Padding(0x9),
        'Hardcoded Value 1' / construct.HexString(construct.Int32ul),
        'Hardcoded Value 2' / construct.HexString(construct.Int32ul),
        'Hardcoded Value 3' / construct.HexString(construct.Int32ul),
        construct.Padding(0x17),
        'Compromised Host IP' / construct.IP4Address,  # Use IP adapter
        # 'Unknown IP Addresses' / construct.Switch(
        #     this['Hardcoded Value 1'],
        #     {
        #         '0x1f4' : EMBED_SPEC
        #     },
        # ),
        'Unknown IP Addresses' / address_struct[4],
        # 'Unknown IP Addresses' / IP4Address[4],
        construct.Padding(8),
        'Unknown Indicator' / construct.String(0xF),
        construct.Padding(2),
        'Number of CPUs' / construct.Int32ul,
        'CPU Mhz' / construct.Int32ul,
        'Total Memory (MB)' / construct.Int32ul,
        'Compromised System Kernel' / construct.CString(),
        'Possible Trojan Version' / construct.CString()
    )

    data = (b'\x01\x00\x00\x00}\x00\x00\x00\x00\xf4\x01\x00\x002\x00\x00\x00\xe8'
            b'\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
            b'\x01\x00\x00\x00\x00\x01\x00\x00\x00\xc0\xa8\x01\r\xc0\xa8\x01\r\xc0'
            b'\xa8\x01\r\xc0\xa8\x01\r\xc0\xa8\x01\r\xff\xff\x01\x00\x00\x00\x00\x00'
            b'-== Love AV ==-:\x00\x01\x00\x00\x00d\n\x00\x00\xc4\x07\x00\x00'
            b'Linux 3.13.0-93-generic\x001:G2.40\x00')

    html_data = construct.html_hex(PACKET, data, depth=1)

    with open(os.path.join(os.path.dirname(__file__), 'construct_html.html'), 'r') as fo:
        expected_html_data = fo.read()

    assert html_data == expected_html_data


def test_base64():
    """Test the Base64 Adapter with bug associated with unicode encoding on build"""
    spec = construct.Base64(construct.CString("utf-16le"))
    data = b'Y\x00W\x00J\x00j\x00Z\x00A\x00=\x00=\x00\x00\x00'
    assert spec.parse(data) == b"abcd"
    assert spec.build(b"abcd") == data

    spec = construct.Base64(construct.CString("utf-8"))
    data = b'YWJjZA==\x00'
    assert spec.parse(data) == b"abcd"
    assert spec.build(b"abcd") == data
