"""This modules contains helper functions for the construct library."""

from __future__ import division

import base64
import os
import io
import re
import string
import sys
import uuid

import construct
from construct import *
from construct.core import globalstringencoding
from construct.lib import py3compat

from mwcp.utils import custombase64, pefileutils

PY3 = sys.version_info.major == 3

# Visible interface. Add the classes and functions you would like to be available for users of construct
# library here.
__all__ = ['BYTE', 'WORD', 'DWORD', 'QWORD', 'ULONG', 'ULONGLONG', 'TerminatedString',
           'CString', 'String', 'String16', 'String32', 'IP4Address', 'SkipNull',
           'HexString', 'Base64', 'UUID', 'PEPhysicalAddress', 'PEPointer', 'PEPointer64',
           'Regex', 'find_constructs', 'Boolean', 'Delimited', 'Printable']

BYTE = Byte
WORD = Int16ul
DWORD = ULONG = Int32ul
QWORD = ULONGLONG = Int64ul

# The pop in construct doesn't properly work. It will raise a ValueError even
# if you provide a default value.
# Therefore we are going to monkey patch a correct implementation.
orig_pop = Container.pop


def pop(self, key, *default):
    try:
        return orig_pop(self, key, *default)
    except ValueError:
        if default:
            return default[0]
        else:
            raise KeyError


Container.pop = pop


def chunk(seq, size):
    """
    Returns an iterator that yields full chunks seq into size chunks.

    >>> list(chunk('hello', 2))
    [('h', 'e'), ('l', 'l')]
    >>> list(chunk('hello!', 2))
    [('h', 'e'), ('l', 'l'), ('o', '!')]
    """
    return zip(*([iter(seq)] * size))


class Boolean(Adapter):
    r"""
    Adapter used to convert parsed value into a boolean.
    NOTE: While similar to construct.Flag, this adapter accepts any value other than 0 or '' as true.
          And will work with more than just construct.Byte.

    WARNING: Due to the lossy nature, this can't be used to build.

    e.g.
    >>> Boolean(Int32ul).parse(b'\x01\x02\x03\x04')
    True
    >>> Boolean(Int32ul).parse(b'\x00\x00\x00\x00')
    False
    >>> Boolean(CString()).parse(b'hello\x00')
    True
    >>> Boolean(CString()).parse(b'\x00')
    False
    """

    def _decode(self, obj, context):
        return bool(obj)


class TerminatedString(construct.StringEncoded):
    r"""Construct adapter that can be used on a string construct to strip away the garbage
    characters after the first instance of the terminator.
    (If the terminator is not found, the whole string is returned back.)

    If used to build, the adapter resorts to the default build instructions.

    e.g.
    >>> TerminatedString(String(10)).build(b'hello')
    b'hello\x00\x00\x00\x00\x00'
    >>> TerminatedString(PascalString(Byte)).build(b'hello')
    b'\x05hello'
    >>> TerminatedString(String(10)).parse(b'hello\x00\x02\x04FA')
    'hello'
    >>> TerminatedString(String(10)).parse(b'helloworld')
    'helloworld'
    >>> TerminatedString(GreedyString()).parse(b'this is a valid string\x00\x00 GARBAGE!')
    b'this is a valid string'
    >>> TerminatedString(PascalString(Byte)).parse(b'\x0Ahello\x00\x01\x03\x04F')
    b'hello'
    """
    __slots__ = ["encoding", "terminator"]

    def __init__(self, subcon, encoding=None, terminator='\x00'):
        super(TerminatedString, self).__init__(subcon, encoding)
        if not isinstance(terminator, str):
            raise ValueError('Terminator must be str and not bytes.')
        self.terminator = terminator

    def _decode(self, obj, context):
        obj = super(TerminatedString, self)._decode(obj, context)
        if isinstance(obj, bytes):
            # Sometimes obj will be bytes if an encoding wasn't specified.
            terminator = self.terminator.encode()
        else:
            terminator = self.terminator
        # Strip everything after terminator.
        obj, _, _ = obj.partition(terminator)
        return obj


def CString(terminator=b"\x00", encoding=None):
    r"""
    This is an alternative of implementation of construct.CString() that fixes the issues with
    working with utf-16 or utf-32 encoded strings (github.com/construct/construct/issues/388)

    >>> CString().parse(b'hello\x00')
    b'hello'
    >>> CString(encoding='utf-16').parse(b'\xff\xfeh\x00e\x00l\x00l\x00o\x00\x00\x00')  # FFFE is BOM for utf-16-le
    'hello'
    >>> CString(encoding='utf-16').parse(b'h\x00e\x00l\x00l\x00o\x00\x00\x00')
    'hello'
    >>> CString(encoding='utf-16').build('hello')
    b'\xff\xfeh\x00e\x00l\x00l\x00o\x00\x00\x00'
    >>> CString(encoding='utf-32').build('hello')
    b'\xff\xfe\x00\x00h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00\x00\x00\x00\x00'

    Make sure to specify 'le' or 'be' in the encoding if you don't want BOM markers when building.
    >>> CString(encoding='utf-32-le').build('hello')
    b'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00\x00\x00\x00\x00'
    >>> CString(encoding='utf-32-be').build('hello')
    b'\x00\x00\x00h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00\x00'
    """
    # Revert to original if not utf-16 or utf-32.
    if not encoding or not ('16' in encoding or '32' in encoding):
        return construct.CString(terminators=terminator, encoding=encoding)

    size = 4 if '32' in encoding else 2
    if len(terminator) == 1:
        terminator = terminator * size
    assert len(terminator) == size

    return construct.StringEncoded(
        construct.ExprAdapter(
            RepeatUntil(lambda obj, lst, ctx: obj == terminator, Bytes(size)),
            encoder=lambda obj, ctx: list(map(b''.join, chunk(py3compat.iteratebytes(obj), size))) + [terminator],
            decoder=lambda obj, ctx: b''.join(obj[:-1])),
        encoding)


def String(length, encoding=None, padchar=b"\x00", paddir="right", trimdir="right"):
    r"""
    A configurable, fixed-length or variable-length string field.

    This is a modified version of the original construct.String that properly handles multi-byte encodings
    (utf-16, utf-32).

    NOTE: When using this to build a multi-byte encoded string you need to be aware of the extra space that can be taken
    up by BOM markings when specifying the length.
    If you don't want BOM. Make sure to explicitly specify "le" or "be" at the end of your encoding.
    >>> u'hi'.encode('utf-16')
    b'\xff\xfeh\x00i\x00'
    >>> u'hi'.encode('utf-16-le')
    b'h\x00i\x00'

    :param length: length in bytes (not unicode characters), as int or context function
    :param encoding: encoding (e.g. "utf8") or None for bytes
    :param padchar: b-string character to pad out strings (by default b"\x00")
    :param paddir: direction to pad out strings (one of: right left both)
    :param trimdir: direction to trim strings (one of: right left)

    e.g.
    >>> construct.StringEncoded(Bytes(10), 'utf-16').parse(b'h\x00e\x00l\x00l\x00o\x00')
    'hello'
    >>> String(10, encoding='utf-16').parse(b'h\x00e\x00l\x00l\x00o\x00')
    'hello'
    >>> String(12, encoding='utf-16').build(u'hello')
    b'\xff\xfeh\x00e\x00l\x00l\x00o\x00'
    >>> String(10, encoding='utf-16le').build(u'hello')
    b'h\x00e\x00l\x00l\x00o\x00'
    >>> String(16, encoding='utf-16le').build(u'hello')
    b'h\x00e\x00l\x00l\x00o\x00\x00\x00\x00\x00\x00\x00'
    >>> String(16, encoding='utf-16').parse(b'h\x00e\x00l\x00l\x00o\x00\x00\x00\x00\x00\x00\x00')
    'hello'

    Works with utf-32 in the same way.
    >>> String(20, encoding='utf-32-le').build(u'hello')
    b'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00'
    >>> String(20, encoding='utf-32').parse(b'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00')
    'hello'

    Also, still works with regular single byte encodings.
    >>> String(5).build(b'hello')
    b'hello'
    >>> String(5).parse(b'hello')
    b'hello'
    """
    if not encoding or not ('16' in encoding or '32' in encoding):
        return construct.String(length, encoding=encoding, padchar=padchar, paddir=paddir, trimdir=trimdir)

    if '32' in encoding:
        byte_size = 4
    elif '16' in encoding:
        byte_size = 2
    else:
        byte_size = 1

    # Determine if we need to account for BOM markings.
    bom_bytes = len(u'\x00'.encode(encoding)) - byte_size

    if callable(length):
        decoded_length = lambda ctx: (length(ctx) - bom_bytes) // byte_size
    else:
        decoded_length = (length - bom_bytes) // byte_size

    # Fake the StringPaddedTrimmed so that it can be used with non-byte padchar.
    class _StringPaddedTrimmed(construct.StringPaddedTrimmed):
        """Overwritten to allow padchar to be a str type."""

        def __init__(self, length, subcon, padchar=b"\x00", paddir="right", trimdir="right"):
            # Fake the padchar as a byte the switch it back.
            orig_padchar = padchar
            super(_StringPaddedTrimmed, self).__init__(
                length, subcon, padchar=b'\x00', paddir=paddir, trimdir=trimdir)
            self.padchar = orig_padchar

    # Decode padchar to str string to match StringEncoded.
    encoding = encoding or globalstringencoding
    if encoding and isinstance(padchar, bytes):
        padchar = padchar.decode()

    # We flipped StringPaddedTrimmed and StringEncoded from what the original was doing so our string gets
    # decoded before the null characters get stripped.
    return _StringPaddedTrimmed(
        decoded_length,
        construct.StringEncoded(Bytes(length), encoding),
        padchar=padchar,
        paddir=paddir,
        trimdir=trimdir
    )


def String16(length):
    r"""
    Creates UTF-16 (little endian) encoded string.

    >>> String16(10).build('hello')
    b'h\x00e\x00l\x00l\x00o\x00'
    >>> String16(10).parse(b'h\x00e\x00l\x00l\x00o\x00')
    'hello'
    >>> String16(16).parse(b'h\x00e\x00l\x00l\x00o\x00\x00\x00\x00\x00\x00\x00')
    'hello'
    """
    return String(length, encoding='utf-16-le')


def String32(length):
    r"""
    Creates UTF-32 (little endian) encoded string.

    >>> String32(20).build('hello')
    b'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00'
    >>> String32(20).parse(b'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00')
    'hello'
    """
    return String(length, encoding='utf-32-le')


class Printable(Validator):
    r"""
    Validator used to validate that a parsed String (or Bytes) is a printable (ascii) string.

    NOTE: A ValidationError is a type of ConstructError and will be cause if catching ConstructError.

    >>> Printable(String(5)).parse(b'hello')
    'hello'
    >>> Printable(String(5)).parse(b'he\x11o!')
    Traceback (most recent call last):
        ...
    construct.core.ValidationError: ('object failed validation', 'he\x11o!')
    >>> Printable(Bytes(3)).parse(b'\x01NO')
    Traceback (most recent call last):
        ...
    construct.core.ValidationError: ('object failed validation', b'\x01NO')
    >>> Printable(Bytes(3)).parse(b'YES')
    b'YES'
    """

    def _validate(self, obj, context):
        if PY3 and isinstance(obj, bytes):
            return all(chr(byte) in string.printable for byte in obj)
        return isinstance(obj, py3compat.stringtypes) and all(char in string.printable for char in obj)


class IP4AddressAdapter(Adapter):
    r"""
    Adapter used to format a IP address from a list of four ints.

    e.g.
    >>> IP4AddressAdapter(Byte[4]).parse(b'\x01\x02\x03\x04')
    '1.2.3.4'
    >>> IP4AddressAdapter(Int16ul[4]).parse(b'\x01\x00\x02\x00\x03\x00\x04\x00')
    '1.2.3.4'
    """

    def _encode(self, obj, context):
        return list(map(int, obj.split('.')))

    def _decode(self, obj, context):
        return '{0}.{1}.{2}.{3}'.format(*obj)


# An IP4Address parsed from single bytes.
IP4Address = IP4AddressAdapter(Byte[4])

# Continuously parses until it hits the first non-zero byte.
SkipNull = Const(b'\x00')[:]


class HexString(Adapter):
    r"""
    Adapter used to convert an int into a hex string equivalent.

    e.g.
    >>> HexString(Int32ul).build('0x123')
    b'#\x01\x00\x00'
    >>> HexString(Int32ul).parse(b'\x20\x01\x00\x00')
    '0x120'
    >>> HexString(Int16ub).parse(b'\x12\x34')
    '0x1234'
    >>> HexString(BytesInteger(20)).parse(b'\x01' * 20)
    '0x101010101010101010101010101010101010101'
    """

    def _encode(self, obj, context):
        return int(obj, 16)

    def _decode(self, obj, context):
        hex_string = hex(obj)
        if hex_string.endswith('L'):
            hex_string = hex_string[:-1]
        return hex_string


class Base64(Adapter):
    r"""
    Adapter used to Base64 encoded/decode a value.

    :param subcon: the construct to wrap
    :param str custom_alpha: optional custom alphabet to use

    e.g.
    >>> Base64(GreedyString()).build(b'hello')
    b'aGVsbG8='
    >>> Base64(GreedyString()).parse(b'aGVsbG8=')
    b'hello'
    >>> Base64(GreedyBytes).build(b'\x01\x02\x03\x04')
    b'AQIDBA=='
    >>> Base64(GreedyBytes).parse(b'AQIDBA==')
    b'\x01\x02\x03\x04'

    NOTE: String size is based on the encoded version.
    >>> Base64(String(16)).build(b'hello world')
    b'aGVsbG8gd29ybGQ='
    >>> Base64(String(16)).parse(b'aGVsbG8gd29ybGQ=')
    b'hello world'

    Supplying a custom alphabet is also supported.
    >>> spec = Base64(String(16), custom_alpha='EFGHQRSTUVWefghijklmnopIJKLMNOPABCDqrstuvwxyXYZabcdz0123456789+/=')
    >>> spec.build(b'hello world')
    b'LSoXMS8BO29dMSj='
    >>> spec.parse(b'LSoXMS8BO29dMSj=')
    b'hello world'
    """
    __slots__ = ['subcon', 'custom_alpha']

    def __init__(self, subcon, custom_alpha=None):
        super(Base64, self).__init__(subcon)
        self.custom_alpha = custom_alpha

    def _encode(self, obj, context):
        if self.custom_alpha:
            return custombase64.b64encode(obj, self.custom_alpha)
        else:
            return base64.b64encode(obj)

    def _decode(self, obj, context):
        try:
            if self.custom_alpha:
                return custombase64.b64decode(obj, self.custom_alpha)
            else:
                return base64.b64decode(obj)
        except TypeError as e:
            raise ConstructError('[*] Error while Base64 decoding provided data: {}'.format(e))


class UUIDAdapter(Adapter):
    r"""
    Adapter used to convert parsed bytes to a string representing the UUID.
    Adapter can decode 16 bytes straight or in little-endian order if you set le=True.

    e.g.
    >>> UUIDAdapter(Bytes(16)).build('{12345678-1234-5678-1234-567812345678}')
    b'xV4\x124\x12xV\x124Vx\x124Vx'
    >>> UUIDAdapter(Bytes(16), le=False).build('{12345678-1234-5678-1234-567812345678}')
    b'\x124Vx\x124Vx\x124Vx\x124Vx'
    >>> UUIDAdapter(Bytes(16)).parse(b'xV4\x124\x12xV\x124Vx\x124Vx')
    '{12345678-1234-5678-1234-567812345678}'
    """
    __slots__ = ['subcon', 'le']

    def __init__(self, subcon, le=True):
        super(UUIDAdapter, self).__init__(subcon)
        self.le = le

    def _encode(self, obj, context):
        obj = uuid.UUID(obj)
        if self.le:
            return obj.bytes_le
        else:
            return obj.bytes

    def _decode(self, obj, context):
        if self.le:
            _uuid = uuid.UUID(bytes_le=obj)
        else:
            _uuid = uuid.UUID(bytes=obj)
        return '{' + str(_uuid) + '}'


def UUID(le=True):
    r"""A convenience function for using the UUIDAdapter with 16 bytes.

    :param le: Whether to use "bytes_le" or "bytes" when constructing the UUID.

    e.g.
    >>> UUID().build('{12345678-1234-5678-1234-567812345678}')
    b'xV4\x124\x12xV\x124Vx\x124Vx'
    >>> UUID(le=False).build('{12345678-1234-5678-1234-567812345678}')
    b'\x124Vx\x124Vx\x124Vx\x124Vx'
    >>> UUID().parse(b'xV4\x124\x12xV\x124Vx\x124Vx')
    '{12345678-1234-5678-1234-567812345678}'
    >>> UUID(le=False).parse(b'\x124Vx\x124Vx\x124Vx\x124Vx')
    '{12345678-1234-5678-1234-567812345678}'
    """
    return UUIDAdapter(Bytes(16), le=le)


def _get_pe(context):
    """Gets the PE the user passed in initially to the context."""
    while '_' in context:
        context = context['_']
    if 'pe' not in context:
        raise ValueError('Missing pe parameter.')
    return context.pe


class PEPhysicalAddress(Adapter):
    r"""
    Adapter used to convert an int representing a PE memory address into a physical address.

    The PE object can either be passed into the specific construct, or as a keyword arument in
    the parse()/build() functions.
    If passed in through parse()/build(), the same PE object will be used for all instances.

    This Adapter is useful when used along-side the Pointer construct:
    spec = Struct(
        'offset' / PEPhysicalAddress(Int32ul),
        'data' / Pointer(this.offset, Bytes(100))
    )

    e.g.
    >>> with open(r'C:\32bit_exe', 'rb') as fo:
    ...     file_data = fo.read()
    >>> pe = pefileutils.obtain_pe(file_data)
    >>> PEPhysicalAddress(Int32ul, pe=pe).build(100)
    b'd\x00@\x00'
    >>> PEPhysicalAddress(Int32ul, pe=pe).parse(b'd\x00@\x00')
    100
    >>> PEPhysicalAddress(Int32ul).build(100, pe=pe)
    b'd\x00@\x00'
    >>> PEPhysicalAddress(Int32ul).parse(b'd\x00@\x00', pe=pe)
    100
    """

    def __init__(self, subcon, pe=None):
        """
        :param pe: Optional PE file object. (if not supplied here, this must be supplied during parse()/build()
        :param subcon: subcon to parse memory offset.
        """
        super(PEPhysicalAddress, self).__init__(subcon)
        self._pe = pe

    def _encode(self, obj, context):
        pe = self._pe or _get_pe(context)
        address = pefileutils.obtain_memory_offset(obj, pe=pe)
        if address is None:
            raise ConstructError('Unable to encode physical address.')
        return address

    def _decode(self, obj, context):
        pe = self._pe or _get_pe(context)
        address = pefileutils.obtain_physical_offset(obj, pe=pe)
        if address is None:
            raise ConstructError('Unable to decode virtual address.')
        return address


def PEPointer(mem_off, subcon, pe=None):
    r"""
    This is an alternative to PEPhysicalAddress when you are using the address along with Pointer

    Simplifies:
    spec = Struct(
        'offset' / PEPhysicalAddress(Int32ul),
        'data' / Pointer(this.offset, Bytes(100))
    )
    to:
    spec = Struct(
        'offset' / Int32ul,
        'data' / PEPointer(this.offset, Bytes(100))
    )

    spec.parse(file_data, pe=pe_object)

    :param mem_off: an int or a function that represents the memory offset for the equivalent physical offset.
    :param subcon: the subcon to use at the offset
    :param pe: Optional PE file object. (if not supplied here, this must be supplied during parse()/build()
    """

    def _obtain_physical_offset(ctx):
        _pe = pe or _get_pe(ctx)
        _mem_off = mem_off(ctx) if callable(mem_off) else mem_off
        phy_off = pefileutils.obtain_physical_offset(_mem_off, pe=_pe)
        if phy_off is None:
            raise ConstructError('Unable to decode virtual address')
        return phy_off

    return Pointer(_obtain_physical_offset, subcon)


def PEPointer64(mem_off, inst_end, subcon, pe=None):
    r"""
    This is the 64-bit version of PEPointer.
    This subconstruct takes an extra argument which specifies
    the location of the end of the instruction for which the memory_offset was used.
    (A parameter necessary for 64-bit)

    Example:
    spec = Struct(
        'offset' / Int32ul,
        Padding(2),
        'inst_end' / Tell,
        'data' / PEPointer64(this.offset, this.inst_end, Byte(100))
    )

    spec = Struct(
        'instruction' / Regex(
            '\x01\x03(?P<data_ptr>.{4})\x04\x05(?P<end>)\x06\x07', data_ptr=DWORD, end=Tell),
        'data' / PEPointer64(this.instruction.data_ptr, this.instruction.end, Bytes(100))
    )

    spec.parse(file_data, pe=pe_object)

    :param mem_off: an int or a function that represents the memory offset for the equivelent physical offset.
    :param inst_end: an int or a function that represents the location of the end of the instruction to be relative to.
    :param subcon: the subcon to use at the offset
    :param pe: Optional PE file object. (if not supplied here, this must be supplied during parse()/build()
    """

    def _obtain_physical_offset(ctx):
        _pe = pe or _get_pe(ctx)
        _mem_off = mem_off(ctx) if callable(mem_off) else mem_off
        _inst_end = inst_end(ctx) if callable(inst_end) else inst_end
        phy_off = pefileutils.obtain_physical_offset_x64(_mem_off, _inst_end, pe=_pe)
        if phy_off is None:
            raise ConstructError('Unable to decode virtual address')
        return phy_off

    return Pointer(_obtain_physical_offset, subcon)


class Delimited(Construct):
    r"""
    A construct used to parse delimited data.

    NOTE: The parsed constructs will be buffered

    >>> spec = Delimited(b'|',
    ...     'first' / CString(),
    ...     'second' / Int32ul,
    ...     # When using a Greedy construct, either all data till EOF or the next delimiter will be consumed.
    ...     'third' / GreedyBytes,
    ...     'fourth' / Byte
    ... )
    >>> spec.parse(b'Hello\x00\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff')
    Container(first=b'Hello')(second=1)(third=b'world!!\x01\x02')(fourth=255)
    >>> spec.build(dict(first=b'Hello', second=1, third=b'world!!\x01\x02', fourth=255))
    b'Hello\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff'

    If you don't care about a particular element, you can leave it nameless just like in Structs.
    # NOTE: You can't build unless you have supplied every attribute.
    >>> spec = Delimited(b'|',
    ...     'first' / CString(),
    ...     'second' / Int32ul,
    ...     Pass,
    ...     'fourth' / Byte
    ... )
    >>> spec.parse(b'Hello\x00\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff')
    Container(first=b'Hello')(second=1)(fourth=255)

    It may also be useful to use Pass or Optional for fields that may not exist.
    >>> spec = Delimited(b'|',
    ...     'first' / CString(),
    ...     'second' / Pass,
    ...     'third' / Optional(Int32ul)
    ... )
    >>> spec.parse(b'Hello\x00\x00|dont care|\x01\x00\x00\x00')
    Container(first=b'Hello')(second=None)(third=1)
    >>> spec.parse(b'Hello\x00\x00||')
    Container(first=b'Hello')(second=None)(third=None)
    """

    __slots__ = ['delimiter', 'subcons']

    def __init__(self, delimiter, *subcons):
        """
        :param delimiter: single charactor or a function that takes context and returns the delimiter
        :param subcons: constructs to use to parse each element.
                    NOTE: The number of constructs will be the number of elements delimited.
                    (ie. len(subcons) == number of delimiters + 1)

        :raises ValueError: If no subcons are defined.
        """
        super(Delimited, self).__init__()
        self.delimiter = delimiter
        self.subcons = subcons
        if not subcons:
            raise ValueError('At least one subconstruct must be defined.')

    def _parse(self, stream, context, path):
        delimiter = self.delimiter(context) if callable(self.delimiter) else self.delimiter
        if not isinstance(delimiter, bytes) or len(delimiter) != 1:
            raise ValueError('Invalid delimiter.')

        obj = Container()
        context = Container(_=context)

        # Parse all by the last element.
        for sc in self.subcons[:-1]:
            # Don't count probes as an element.
            if isinstance(sc, Probe):
                sc._parse(stream, context, path)
                continue

            # Read bytes until we find delimiter.
            start_offset = stream.tell()
            data = []
            for byte in iter(lambda: stream.read(1), ''):
                if byte == delimiter:
                    break
                data.append(byte)
            else:
                raise ConstructError('Unable to find delimiter: {}'.format(delimiter))

            sub_stream = io.BytesIO(b''.join(data))
            orig_tell = sub_stream.tell
            # Fake the tell() so that RawCopy and Tell still works.
            # TODO: This is a little hacky, figure out a better way to preserve stream offsets but still allow
            # the user to easily request all bytes between two delimiters.
            sub_stream.tell = lambda: start_offset + orig_tell()
            subobj = sc._parse(sub_stream, context, path)
            if sc.flagembedded:
                if subobj is not None:
                    obj.update(subobj.items())
                    context.update(subobj.items())
            else:
                if sc.name is not None:
                    obj[sc.name] = subobj
                    context[sc.name] = subobj

        # Parse the last element.
        sc = self.subcons[-1]
        subobj = sc._parse(stream, context, path)
        if sc.flagembedded:
            if subobj is not None:
                obj.update(subobj.items())
                context.update(subobj.items())
        else:
            if sc.name is not None:
                obj[sc.name] = subobj
                context[sc.name] = subobj

        return obj

    def _build(self, obj, stream, context, path):
        delimiter = self.delimiter(context) if callable(self.delimiter) else self.delimiter
        if not isinstance(delimiter, bytes) or len(delimiter) != 1:
            raise ValueError('Invalid delimiter.')

        context = Container(_=context)
        context.update(obj)
        for i, sc in enumerate(self.subcons):
            if sc.flagembedded:
                subobj = obj
            elif sc.flagbuildnone:
                subobj = obj.get(sc.name, None)
            else:
                subobj = obj[sc.name]
            buildret = sc._build(subobj, stream, context, path)
            if buildret is not None:
                if sc.flagembedded:
                    context.update(buildret)
                if sc.name is not None:
                    context[sc.name] = buildret
            # Add delimiter if not last element and not Probe.
            if i < len(self.subcons) - 1 and not isinstance(sc, Probe):
                stream.write(delimiter)
        return context


class Regex(Construct):
    r"""
    A construct designed look for the first match for the given regex, then parse the data collected in the groups.
    Returns the matched capture groups in attributes based on their respective names.
    If a subconstruct is defined for a group, it will run that construct on that particular piece of data.

    NOTE: The subconstruct will run on the data as if is the only data that exists. Therefore, using Seek and Tell
    will be purely relative to that piece of data only. This was done to ensure you are only parsing what has been
    captured. (If you need to use Seek or Tell, you will have to instead make a capture group that collects no data.)

    NOTE: If you supply a string as the regular expression, the re.DOTALL flag will be automatically specified.
    If you need to use different flags, you must pass a compiled regex.

    The seek position is left at the end of the successful match (match.end()).

    >>> regex = re.compile(b'\x01\x02(?P<size>.{4})\x03\x04(?P<path>[A-Za-z].*\x00)', re.DOTALL)
    >>> data = b'GARBAGE!\x01\x02\x0A\x00\x00\x00\x03\x04C:\Windows\x00MORE GARBAGE!'
    >>> Regex(regex, size=Int32ul, path=CString()).parse(data)
    Container(size=10)(path=b'C:\\Windows')
    >>> Regex(regex).parse(data)
    Container(size=b'\n\x00\x00\x00')(path=b'C:\\Windows\x00')
    >>> Struct(
    ...     're' / Regex(regex, size=Int32ul, path=CString()),
    ...     'after_re' / Tell,
    ...     'garbage' / GreedyBytes
    ... ).parse(data)
    Container(re=Container(size=10)(path=b'C:\\Windows'))(after_re=27)(garbage=b'MORE GARBAGE!')
    >>> Struct(
    ...     Embedded(Regex(regex, size=Int32ul, path=CString())),
    ...     'after_re' / Tell,
    ...     'garbage' / GreedyBytes
    ... ).parse(data)
    Container(size=10)(path=b'C:\\Windows')(after_re=27)(garbage=b'MORE GARBAGE!')

    You can use Regex as a trigger to find a particular piece of data before you start parsing.
    >>> Struct(
    ...     Regex('TRIGGER'),
    ...     'greeting' / CString()
    ... ).parse(b'\x01\x02\x04GARBAGE\x05TRIGGERhello world\x00')
    Container(greeting=b'hello world')

    If no data is captured, the associated subcon will received a stream with the position set at the location
    of that captured group. Thus, allowing you to use it as an anchor point.
    >>> Regex('hello (?P<anchor>)world(?P<extra_data>.*)', anchor=Tell).parse(b'hello world!!!!')
    Container(anchor=6)(extra_data=b'!!!!')

    If no named capture groups are used, you can instead parse the entire matched string by supplying
    a subconstruct as a positional argument. (If no subcon is provided, the raw bytes are returned instead.
    >>> Regex('hello world\x00', CString()).parse(b'GARBAGE\x01\x03hello world\x00\x04')
    b'hello world'
    >>> Regex('hello world\x00').parse(b'GARBAGE\x01\x03hello world\x00\x04')
    b'hello world\x00'

    You can also set the regular expression to match in-place (instead of searching the data)
    by setting the keyword argument _match to True.
    >>> Regex('hello', _match=True).parse(b'hello world!')
    b'hello'
    >>> Regex('hello').parse(b'bogus hello world')
    b'hello'
    >>> Regex('hello', _match=True).parse(b'bogus hello world')
    Traceback (most recent call last):
        ...
    construct.core.ConstructError: regex did not match
    """

    __slots__ = ['regex', 'subcon', 'group_subcons', 'match']

    def __init__(self, regex, *subcon, **group_subcons):
        """
        Initializes regex construct.

        :param regex: A regex to use (can be a string or compiled).
        :param subcon:
            A subcon to use on the entire matching string when there are no named capture groups.
            (NOTE: This is only used if there are no capture groups.
            If you want to use capture groups AND this then have a capture group encapsulating the entire regex.)
        :param group_subcons:
            Keyword argument dictionary that contains the constructs to use for the corresponding capture group.
            If a subcon is not supplied for a capture group, it will default to returning bytes
            (equivalent to setting construct.Bytes() for that group.)

        :raises ValueError: If arguments are invalid.
        """
        super(Regex, self).__init__()
        if PY3 and isinstance(regex, str):
            regex = regex.encode()  # force byte strings
        if isinstance(regex, bytes):
            regex = re.compile(regex, re.DOTALL)
        self.regex = regex
        # TODO: This feature seems backwards, perhaps make a _search keyword instead and default to match functionality.
        # Alternatively, we could have RegexSearch and RegexMatch constructs instead.
        self.match = group_subcons.pop('_match', False)
        self.group_subcons = group_subcons
        if subcon and len(subcon) > 1:
            raise ValueError('Only one subcon can be supplied for the entire match.')
        if subcon and group_subcons:
            raise ValueError('subcon and group_subcons arguments cannot be used at the same time.')
        self.subcon = subcon[0] if subcon else None

    def _parse(self, stream, context, path):
        start = stream.tell()
        # NOTE: we are going to have to read the entire stream due to regex requirements.
        # However, that's okay in this case since we are parsing ByteIO anyway.
        if self.match:
            match = self.regex.match(stream.read())
        else:
            match = self.regex.search(stream.read())
        if not match:
            raise ConstructError('regex did not match')

        try:
            group_dict = match.groupdict()

            # If there are no named groups. Return parsed full match instead.
            if not group_dict:
                if self.subcon:
                    sub_stream = io.BytesIO(match.group())
                    return self.subcon._parse(sub_stream, context, path)
                else:
                    return match.group()

            # Otherwise, we are going to parse each named capture group.
            obj = Container()
            context = Container(_=context)

            # Default to displaying matched data as pure bytes.
            obj.update(group_dict)
            context.update(group_dict)

            # Parse groups using supplied constructs.
            for name, subcon in self.group_subcons.items():
                try:
                    data = match.group(name)
                except IndexError:
                    continue

                # If we have an empty capture group, the user would like to use it as an anchor.
                if not data:
                    stream.seek(start + match.start(name))
                    sub_stream = stream
                else:
                    sub_stream = io.BytesIO(data)

                try:
                    subobj = subcon._parse(sub_stream, context, path)
                except ConstructError as e:
                    # Raise a more useful error message.
                    raise ConstructError('Failed to parse {} capture group with error: {}'.format(name, e))
                obj[name] = subobj
                context[name] = subobj
            return obj

        finally:
            # Reset position to right after the matched regex.
            stream.seek(start + match.end())


def find_constructs(struct, data):
    r"""
    Generator that yields the results of successful parsings of the given
    construct.
    Note: Construct must attempt to read something. Ie, don't have a Peek
    as your first subconstruct.

    Also, it's best if you have some type of validation (Const, OneOf, NoneOf, Check, etc) within your struct.
    Otherwise, it makes more sense to use a GreedyRange (the '[:]' notation) instead of this function.

    e.g.
    >>> struct = Struct(
    ...     Const(b'MZ'),
    ...     'int' / Int16ul,
    ...     'string' / CString())
    >>> list(find_constructs(struct, b'\x01\x02\x03MZ\x0A\x00hello\x00\x03\x04MZ\x0B\x00world\x00\x00'))
    [(3, Container(int=10)(string=b'hello')), (15, Container(int=11)(string=b'world'))]
    >>> list(find_constructs(struct, b'nope'))
    []

    :param struct: construct to apply (instance of construct.Construct)
    :param data: byte string of data to search.

    :yield: tuple containing (offset with data, result Container class)
    """
    data = io.BytesIO(data)

    while True:
        offset = data.tell()
        try:
            data_element = struct.parse_stream(data)
        except construct.ConstructError:
            data.seek(offset + 1)
        else:
            yield offset, data_element

        # Test if we hit end of data.
        if data.read(1):
            data.seek(-1, os.SEEK_CUR)
        else:
            break
