"""
Network constructs
"""

from .version28 import *


class _MACAddressAdapter(Adapter):
    r"""
    Adapter used to format a MAC address from a list of 6 bytes

    e.g.
    >>> _MACAddressAdapter(Byte[6]).parse(b'\x00\x0c\x29\xd3\x91\xbc')
    '00-0c-29-d3-91-bc'
    """
    def _encode(self, obj, context, path):
        return list(map(chr, obj.split("-")))

    def _decode(self, obj, context, path):
        return '{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}'.format(*obj)


# A MacAddress parsed from single bytes.
MacAddress = _MACAddressAdapter(Byte[6])


class _IP4AddressAdapter(Adapter):
    r"""
    Adapter used to format a IP address from a list of four ints.

    e.g.
    >>> _IP4AddressAdapter(Byte[4]).parse(b'\x01\x02\x03\x04')
    '1.2.3.4'
    >>> _IP4AddressAdapter(Int16ul[4]).parse(b'\x01\x00\x02\x00\x03\x00\x04\x00')
    '1.2.3.4'
    """

    def _encode(self, obj, context, path):
        return list(map(int, obj.split('.')))

    def _decode(self, obj, context, path):
        return '{0}.{1}.{2}.{3}'.format(*obj)


# An IP4Address parsed from single bytes.
IP4Address = _IP4AddressAdapter(Byte[4])
