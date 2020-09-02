"""This modules contains helper functions for the construct library."""

import os
import io
import re
import string
import uuid
import zlib

from mwcp.utils import custombase64, elffileutils, pefileutils


# Patch with version 2.8 changes.
from mwcp.utils.construct import version28 as construct
from .version28 import *


BYTE = Byte
WORD = Int16ul
DWORD = ULONG = Int32ul
QWORD = ULONGLONG = Int64ul


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

    def _decode(self, obj, context, path):
        return bool(obj)


class ErrorMessage(Construct):
    r"""
    Raises an exception when triggered by parse or build. Can be used as a sentinel that blows a whistle when a conditional branch goes the wrong way, or to raise an error explicitly the declarative way.
    This modification allows the ability to supply a custom message.

    Example::

        >>> d = "x"/Int8sb >> IfThenElse(this.x > 0, Int8sb, ErrorMessage('Failed if statement'))
        >>> d.parse(b"\xff\x05")
        Traceback (most recent call last):
            ...
        ExplicitError: Failed if statement
    """
    __slots__ = ['message']

    def __init__(self, message="Error field was activated."):
        super(self.__class__, self).__init__()
        self.message = message

    def _parse(self, stream, context, path):
        message = self.message(context) if callable(self.message) else self.message
        raise ExplicitError(message)

    def _build(self, obj, stream, context, path):
        message = self.message(context) if callable(self.message) else self.message
        raise ExplicitError(message)


def String16(length):
    r"""
    Creates UTF-16 (little endian) encoded string.

    >>> String16(10).build(u'hello')
    'h\x00e\x00l\x00l\x00o\x00'
    >>> String16(10).parse(b'h\x00e\x00l\x00l\x00o\x00')
    u'hello'
    >>> String16(16).parse(b'h\x00e\x00l\x00l\x00o\x00\x00\x00\x00\x00\x00\x00')
    u'hello'
    """
    return String(length, encoding='utf-16-le')


def String32(length):
    r"""
    Creates UTF-32 (little endian) encoded string.

    >>> String32(20).build(u'hello')
    'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00'
    >>> String32(20).parse(b'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00')
    u'hello'
    """
    return String(length, encoding='utf-32-le')


class Printable(Validator):
    r"""
    Validator used to validate that a parsed String (or Bytes) is a printable (ascii) string.

    NOTE: A ValidationError is a type of ConstructError and will be cause if catching ConstructError.

    >>> Printable(String(5)).parse(b'hello')
    u'hello'
    >>> Printable(String(5)).parse(b'he\x11o!')
    Traceback (most recent call last):
        ...
    ValidationError: object failed validation: heo!
    >>> Printable(Bytes(3)).parse(b'\x01NO')
    Traceback (most recent call last):
        ...
    ValidationError: object failed validation: NO
    >>> Printable(Bytes(3)).parse(b'YES')
    'YES'
    """

    def _validate(self, obj, context, path):
        if isinstance(obj, bytes):
            return all(chr(byte) in string.printable for byte in obj)
        return isinstance(obj, stringtypes) and all(char in string.printable for char in obj)


# Continuously parses until it hits the first non-zero byte.
SkipNull = Const(b'\x00')[:]

# Continuously parses until it hits the first zero byte (consumed).
# Use this instead of CString() if you can't guarantee it won't fail to decode.
CBytes = NullTerminated(GreedyBytes)


class BytesTerminated(NullTerminated):
    r"""
    BytesTerminated is the same as NullTerminated except that it is targeted for binary data and not strings, and
    therefore the terminator can be an arbitrary length (as opposed to having length equal to the character width).
    See the NullTerminated documentation for the remainder of the functionality and options.

    >>> BytesTerminated(GreedyBytes, term=b'TERM').parse(b'helloTERM')
    'hello'
    """

    # The only method we need to override is _parse. Everything else from NullTerminated works as-is.
    def _parse(self, stream, context, path):
        term = self.term
        term_len = len(term)
        if term_len < 1:
            raise PaddingError("BytesTerminated term must be at least 1 byte")
        data = b''
        while True:
            pos = stream_tell(stream)
            try:
                b = stream_read(stream, term_len)
                stream_seek(stream, pos, 0)
            except StreamError:
                if self.require:
                    raise
                else:
                    stream_seek(stream, pos, 0)
                    data += stream_read_entire(stream)
                    break

            if b == term:
                if self.include:
                    data += b
                if self.consume:
                    stream_read(stream, term_len)
                break
            else:
                data += stream_read(stream, 1)
        if self.subcon is GreedyBytes:
            return data
        if type(self.subcon) is GreedyString:
            return data.decode(self.subcon.encoding)
        return self.subcon._parsereport(io.BytesIO(data), context, path)


# TODO: Make a LStripped?
class Stripped(Adapter):
    r"""
    An adapter that strips characters/bytes from the right of the parsed results.

    NOTE: While this may look similar to Padded() this is different because this
    doesn't take a length and instead strips out the nulls from within the already parsed subconstruct.

    :param subcon: The sub-construct to wrap.
    :param pad: The character/bytes to use for stripping. Defaults to null character.

    >>> Stripped(GreedyBytes).parse(b'hello\x00\x00\x00')
    'hello'
    >>> Stripped(Bytes(10)).parse(b'hello\x00\x00\x00\x00\x00')
    'hello'
    >>> Stripped(Bytes(14), pad=b'PAD').parse(b'helloPADPADPAD')
    'hello'
    >>> Stripped(Bytes(14), pad=b'PAD').build(b'hello')
    'helloPADPADPAD'
    >>> Stripped(CString(), pad=u'PAD').parse(b'helloPADPAD\x00')
    u'hello'
    >>> Stripped(String(14), pad=u'PAD').parse(b'helloPADPAD\x00\x00\x00')
    u'hello'

    # WARNING: If padding doesn't fit in the perscribed data it will not strip it!
    >>> Stripped(Bytes(13), pad=b'PAD').parse(b'helloPADPADPA')
    'helloPADPADPA'
    >>> Stripped(Bytes(13), pad=b'PAD').build(b'hello')
    Traceback (most recent call last):
        ...
    StreamError: bytes object of wrong length, expected 13, found 5

    # If the wrapped subconstruct's size can't be determine, if defaults to not providing a pad.
    >>> Stripped(CString(), pad=u'PAD').build(u'hello')
    'hello\x00'
    """

    def __init__(self, subcon, pad=None):
        super(Stripped, self).__init__(subcon)
        self.pad = pad

    def _decode(self, obj, context, path):
        pad = self.pad

        if pad is None:
            pad = u'\0' if isinstance(obj, unicodestringtype) else b'\x00'

        if not isinstance(pad, type(obj)):
            raise PaddingError("NullStripped pad must be of the same type: {} vs {}".format(type(pad), type(obj)))

        unit = len(pad)
        if unit < 1:
            raise PaddingError("NullStripped pad must be at least 1 byte")

        obj = obj
        if unit == 1:
            obj = obj.rstrip(pad)
        else:
            tailunit = len(obj) % unit
            end = len(obj)
            if tailunit and obj[-tailunit:] == pad[:tailunit]:
                end -= tailunit
            while end-unit >= 0 and obj[end-unit:end] == pad:
                end -= unit
            obj = obj[:end]

        return obj

    def _encode(self, obj, context, path):
        pad = self.pad

        if pad is None:
            pad = u'\0' if isinstance(self.subcon, StringEncoded) else b'\x00'

        try:
            size = self.subcon._sizeof(context, path)
        except SizeofError:
            return obj  # Don't pad if we can't figure out size.

        unit = len(pad)
        if unit == 1:
            obj = obj.ljust(size, pad)
        # Only pad if it fits in nicely.
        elif (size - len(obj)) % unit == 0:
            obj = (obj + (pad * (size - len(obj))))[:size]

        return obj


class HexString(Adapter):
    r"""
    Adapter used to convert an int into a hex string equivalent.

    e.g.
    >>> HexString(Int32ul).build('0x123')
    '#\x01\x00\x00'
    >>> HexString(Int32ul).parse(b'\x20\x01\x00\x00')
    '0x120'
    >>> HexString(Int16ub).parse(b'\x12\x34')
    '0x1234'
    >>> HexString(BytesInteger(20)).parse(b'\x01' * 20)
    '0x101010101010101010101010101010101010101'
    """

    def _encode(self, obj, context, path):
        return int(obj, 16)

    def _decode(self, obj, context, path):
        hex_string = hex(obj)
        if hex_string.endswith('L'):
            hex_string = hex_string[:-1]
        return hex_string


class Base64(Adapter):
    r"""
    Adapter used to Base64 encoded/decode a value.

    WARNING: This adapter must be used on a unicode string value.

    :param subcon: the construct to wrap
    :param custom_alpha: optional custom alphabet to use

    e.g.
    >>> Base64(GreedyString()).build(b'hello')
    'aGVsbG8='
    >>> Base64(GreedyString()).parse(b'aGVsbG8=')
    'hello'
    >>> Base64(GreedyBytes).build(b'\x01\x02\x03\x04')
    'AQIDBA=='
    >>> Base64(GreedyBytes).parse(b'AQIDBA==')
    '\x01\x02\x03\x04'

    NOTE: String size is based on the encoded version.
    >>> Base64(String(16)).build(u'hello world')
    'aGVsbG8gd29ybGQ='
    >>> Base64(String(16)).parse(b'aGVsbG8gd29ybGQ=')
    'hello world'

    Supplying a custom alphabet is also supported.
    >>> spec = Base64(String(16), custom_alpha='EFGHQRSTUVWefghijklmnopIJKLMNOPABCDqrstuvwxyXYZabcdz0123456789+/=')
    >>> spec.build(u'hello world')
    'LSoXMS8BO29dMSj='
    >>> spec.parse(b'LSoXMS8BO29dMSj=')
    'hello world'
    """
    __slots__ = ['subcon', 'custom_alpha']

    def __init__(self, subcon, custom_alpha=None):
        super(Base64, self).__init__(subcon)
        self.custom_alpha = custom_alpha

    def _encode(self, obj, context, path):
        obj = custombase64.b64encode(obj, alphabet=self.custom_alpha)
        # Convert to unicode if wrapped subcon expects it.
        if isinstance(self.subcon, StringEncoded):
            obj = obj.decode('utf-8')
        return obj

    def _decode(self, obj, context, path):
        if isinstance(obj, str):
            obj = obj.encode('utf-8')
        return custombase64.b64decode(obj, alphabet=self.custom_alpha)


class ZLIB(Adapter):
    r"""
    Adapter used to zlib compress/decompress a data buffer

    :param subcon: The construct to wrap
    :param int level: The zlib compression level
    :param int wbits: The zlib decompression window size
    :param int bufsize: The initial output buffer size

    >>> ZLIB(Bytes(12)).build(b'data')
    'x\x9cKI,I\x04\x00\x04\x00\x01\x9b'
    >>> ZLIB(GreedyBytes, level=0).build(b'data')
    'x\x01\x01\x04\x00\xfb\xffdata\x04\x00\x01\x9b'
    >>> ZLIB(GreedyBytes).parse(b'x^KI,I\x04\x00\x04\x00\x01\x9b')
    'data'
    """
    __slots__ = ["subcon", "wbits", "bufsize", "level"]

    def __init__(self, subcon, wbits=None, bufsize=None, level=None):
        super(ZLIB, self).__init__(subcon)
        self.wbits = wbits
        self.bufsize = bufsize
        self.level = level

    def _encode(self, obj, context, path):
        level = self.level(context) if callable(self.level) else self.level
        if level is not None:
            return zlib.compress(obj, level)
        return zlib.compress(obj)

    def _decode(self, obj, context, path):
        """
        ZLIB decompress a buffer, cannot use bufsize if wbits is not set

        :param obj:
        :param context:

        :return:
        """
        wbits = self.wbits(context) if callable(self.wbits) else self.wbits
        bufsize = self.bufsize(context) if callable(self.bufsize) else self.bufsize
        if wbits is not None and bufsize is not None:
            return zlib.decompress(obj, wbits, bufsize)
        elif wbits is not None:
            return zlib.decompress(obj, wbits)
        return zlib.decompress(obj)


class UUIDAdapter(Adapter):
    r"""
    Adapter used to convert parsed bytes to a string representing the UUID.
    Adapter can decode 16 bytes straight or in little-endian order if you set le=True.

    e.g.
    >>> UUIDAdapter(Bytes(16)).build('{12345678-1234-5678-1234-567812345678}')
    'xV4\x124\x12xV\x124Vx\x124Vx'
    >>> UUIDAdapter(Bytes(16), le=False).build('{12345678-1234-5678-1234-567812345678}')
    '\x124Vx\x124Vx\x124Vx\x124Vx'
    >>> UUIDAdapter(Bytes(16)).parse(b'xV4\x124\x12xV\x124Vx\x124Vx')
    '{12345678-1234-5678-1234-567812345678}'
    """
    __slots__ = ['subcon', 'le']

    def __init__(self, subcon, le=True):
        super(UUIDAdapter, self).__init__(subcon)
        self.le = le

    def _encode(self, obj, context, path):
        obj = uuid.UUID(obj)
        if self.le:
            return obj.bytes_le
        else:
            return obj.bytes

    def _decode(self, obj, context, path):
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
    'xV4\x124\x12xV\x124Vx\x124Vx'
    >>> UUID(le=False).build('{12345678-1234-5678-1234-567812345678}')
    '\x124Vx\x124Vx\x124Vx\x124Vx'
    >>> UUID().parse(b'xV4\x124\x12xV\x124Vx\x124Vx')
    '{12345678-1234-5678-1234-567812345678}'
    >>> UUID(le=False).parse(b'\x124Vx\x124Vx\x124Vx\x124Vx')
    '{12345678-1234-5678-1234-567812345678}'
    """
    return UUIDAdapter(Bytes(16), le=le)


def ELFPointer(mem_off, subcon, elf=None):
    r"""
    Pointer for ELF files. This works for both memory sizes.

    NOTE: This only works for x86 instructions. For other architectures,
    please see the "ELFPointer" within their respective submodules. (e.g. construct.ARM.ELFPointer)

    spec.parse(file_data, pe=elf_object)

    :param mem_off: an int or a function that represents the memory offset for the equivalent physical offset.
    :param subcon: the subcon to use at the offset
    :param elf: Optional elftools.ELFFile file object.
        (if not supplied here, this must be supplied during parse()/build()
    """
    def _obtain_physical_offset(ctx):
        _elf = elf or ctx._params.elf
        _mem_off = mem_off(ctx) if callable(mem_off) else mem_off
        phy_off = elffileutils.obtain_physical_offset(_mem_off, elf=_elf)
        if phy_off is None:
            raise ConstructError('Unable to decode virtual address')
        return phy_off

    return Pointer(_obtain_physical_offset, subcon)


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
    >> with open(r'C:\32bit_exe', 'rb') as fo:
    ...     file_data = fo.read()
    >> pe = pefileutils.obtain_pe(file_data)
    >> PEPhysicalAddress(Int32ul, pe=pe).build(100)
    'd\x00@\x00'
    >> PEPhysicalAddress(Int32ul, pe=pe).parse(b'd\x00@\x00')
    100
    >> PEPhysicalAddress(Int32ul).build(100, pe=pe)
    'd\x00@\x00'
    >> PEPhysicalAddress(Int32ul).parse(b'd\x00@\x00', pe=pe)
    100
    """
    def __init__(self, subcon, pe=None):
        """
        :param pe: Optional PE file object. (if not supplied here, this must be supplied during parse()/build()
        :param subcon: subcon to parse memory offset.
        """
        super(PEPhysicalAddress, self).__init__(subcon)
        self._pe = pe

    def _encode(self, obj, context, path):
        pe = self._pe or context._params.pe
        address = pefileutils.obtain_memory_offset(obj, pe=pe)
        if address is None:
            raise ConstructError('Unable to encode physical address.')
        return address

    def _decode(self, obj, context, path):
        pe = self._pe or context._params.pe
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
        _pe = pe or ctx._params.pe
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
        _pe = pe or ctx._params.pe
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
    Container(first=u'Hello', second=1, third=b'world!!\x01\x02', fourth=255)
    >>> spec.build(dict(first=u'Hello', second=1, third=b'world!!\x01\x02', fourth=255))
    'Hello\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff'

    If you don't care about a particular element, you can leave it nameless just like in Structs.
    # NOTE: You can't build unless you have supplied every attribute.
    >>> spec = Delimited(b'|',
    ...     'first' / CString(),
    ...     'second' / Int32ul,
    ...     Pass,
    ...     'fourth' / Byte
    ... )
    >>> spec.parse(b'Hello\x00\x00|\x01\x00\x00\x00|world!!\x01\x02|\xff')
    Container(first=u'Hello', second=1, fourth=255)

    It may also be useful to use Pass or Optional for fields that may not exist.
    >>> spec = Delimited(b'|',
    ...     'first' / CString(),
    ...     'second' / Pass,
    ...     'third' / Optional(Int32ul)
    ... )
    >>> spec.parse(b'Hello\x00\x00|dont care|\x01\x00\x00\x00')
    Container(first=u'Hello', second=None, third=1)
    >>> spec.parse(b'Hello\x00\x00||')
    Container(first=u'Hello', second=None, third=None)

    delimiters may have a length > 1
    >>> spec = Delimited(b'YOYO',
    ...     'first' / CString(),
    ...     'second' / Int32ul,
    ...     # When using a Greedy construct, either all data till EOF or the next delimiter will be consumed.
    ...     'third' / GreedyBytes,
    ...     'fourth' / Byte
    ... )
    >>> spec.parse(b'Hello\x00\x00YOYO\x01\x00\x00\x00YOYOworld!!YO!!\x01\x02YOYO\xff')
    Container(first=u'Hello', second=1, third=b'world!!YO!!\x01\x02', fourth=255)
    >>> spec.build(dict(first=u'Hello', second=1, third=b'world!!YO!!\x01\x02', fourth=255))
    'Hello\x00YOYO\x01\x00\x00\x00YOYOworld!!YO!!\x01\x02YOYO\xff'

    # TODO: Add support for using a single construct for parsing an unknown number of times
    # (or within a min, max, or exact)
    # (Perhaps call it "Split" to avoid overloading too much functionality.)
    # e.g.
    # >>> spec = Delimited(b'|', GreedyString())
    # >>> spec.parse(b'hello|world')
    # ['hello', 'world']
    # >>> spec.parse(b'hello|world|hi|bob')
    # ['hello', 'world', 'hi', 'bob']
    # >>> spec.parse(b'hello')
    # ['hello']
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
        if len(subcons) < 2:
            raise ValueError('At least two subconstruct must be defined.')

    def _find_delimiter(self, stream, delimiter):
        """
        Finds given delimiter in stream.

        :returns: Stream offset for delimiter.
        :raises ConstructError: If delimiter isn't found.
        """
        fallback = stream.tell()
        try:
            for byte in iter(lambda: stream.read(1), b''):
                if delimiter[0] == ord(byte):
                    delimiter_offset = stream.seek(-1, os.SEEK_CUR)
                    if stream.read(len(delimiter)) == delimiter:
                        return delimiter_offset
                    else:
                        stream.seek(delimiter_offset + 1)
            raise ConstructError('Unable to find delimiter: {}'.format(delimiter))
        finally:
            stream.seek(fallback)

    def _parse_subcon(self, subcon, stream, obj, context, path):
        """Parses and fills obj and context."""
        subobj = subcon._parsereport(stream, context, path)
        if subcon.flagembedded:
            if subobj is not None:
                obj.update(subobj.items())
                context.update(subobj.items())
        else:
            if subcon.name is not None:
                obj[subcon.name] = subobj
                context[subcon.name] = subobj

    def _parse(self, stream, context, path):
        delimiter = self.delimiter(context) if callable(self.delimiter) else self.delimiter
        if not isinstance(delimiter, bytestringtype) or not delimiter:
            raise ValueError('Invalid delimiter.')

        obj = Container()
        context = Container(_=context)

        # Parse all but the last element.
        for sc in self.subcons[:-1]:
            # Don't count probes as an element.
            if isinstance(sc, Probe):
                sc._parsereport(stream, context, path)
                continue

            delimiter_offset = self._find_delimiter(stream, delimiter)

            # Temporaily fake the read() so that we can force EOF before delimiter.
            orig_read = stream.read
            def new_read(size=None):
                max_size = delimiter_offset - stream.tell()
                if size is None:
                    size = max_size
                else:
                    size = min(max_size, size)
                return orig_read(size)
            try:
                stream.read = new_read
                self._parse_subcon(sc, stream, obj, context, path)
            finally:
                stream.read = orig_read

            # Align to after delimiter
            stream.seek(delimiter_offset + len(delimiter))

        # Parse the last element.
        self._parse_subcon(self.subcons[-1], stream, obj, context, path)

        return obj

    def _build(self, obj, stream, context, path):
        delimiter = self.delimiter(context) if callable(self.delimiter) else self.delimiter
        if not isinstance(delimiter, bytestringtype) or not delimiter:
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
    If you need to use different flags, you must past a compiled regex.

    The seek position is left at the end of the successful match (match.end()).

    >>> regex = re.compile('\x01\x02(?P<size>.{4})\x03\x04(?P<path>[A-Za-z].*\x00)', re.DOTALL)
    >>> data = 'GARBAGE!\x01\x02\x0A\x00\x00\x00\x03\x04C:\Windows\x00MORE GARBAGE!'
    >>> r = Regex(regex, size=Int32ul, path=CString()).parse(data)
    >>> r == Container(path=u'C:\\Windows', size=10)
    True
    >>> r = Regex(regex).parse(data)
    >>> r == Container(path=b'C:\\Windows\x00', size=b'\n\x00\x00\x00')
    True
    >>> r = Struct(
    ...     're' / Regex(regex, size=Int32ul, path=CString()),
    ...     'after_re' / Tell,
    ...     'garbage' / GreedyBytes
    ... ).parse(data)
    >>> r == Container(re=Container(path=u'C:\\Windows', size=10), after_re=27L, garbage=b'MORE GARBAGE!')
    True

    # TODO: Unfortunately Embedded() no longer works with the update to 2.9
    # >>> Struct(
    # ...     Embedded(Regex(regex, size=Int32ul, path=CString())),
    # ...     'after_re' / Tell,
    # ...     'garbage' / GreedyBytes
    # ... ).parse(data)
    # Container(path=u'C:\\Windows', size=10, after_re=27L, garbage=b'MORE GARBAGE!')

    You can use Regex as a trigger to find a particular piece of data before you start parsing.
    >>> Struct(
    ...     Regex('TRIGGER'),
    ...     'greeting' / CString()
    ... ).parse('\x01\x02\x04GARBAGE\x05TRIGGERhello world\x00')
    Container(greeting=u'hello world')

    If no data is captured, the associated subcon will received a stream with the position set at the location
    of that captured group. Thus, allowing you to use it as an anchor point.
    >>> r = Regex('hello (?P<anchor>)world(?P<extra_data>.*)', anchor=Tell).parse('hello world!!!!')
    >>> r == Container(extra_data=b'!!!!', anchor=6L)
    True

    If no named capture groups are used, you can instead parse the entire matched string by supplying
    a subconstruct as a positional argument. (If no subcon is provided, the raw bytes are returned instead.
    >>> Regex('hello world\x00', CString()).parse('GARBAGE\x01\x03hello world\x00\x04')
    u'hello world'
    >>> Regex('hello world\x00').parse('GARBAGE\x01\x03hello world\x00\x04')
    'hello world\x00'

    You can also set the regular expression to match in-place (instead of searching the data)
    by setting the keyword argument _match to True.
    >>> Regex('hello', _match=True).parse(b'hello world!')
    'hello'
    >>> Regex('hello').parse(b'bogus hello world')
    'hello'
    >>> Regex('hello', _match=True).parse(b'bogus hello world')
    Traceback (most recent call last):
        ...
    ConstructError: [(parsing)] regex did not match
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
        if isinstance(regex, str):
            regex = regex.encode()  # force byte strings
        if isinstance(regex, bytestringtype):
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
            raise ConstructError('[{}] regex did not match'.format(path))

        try:
            group_dict = match.groupdict()

            # If there are no named groups. Return parsed full match instead.
            if not group_dict:
                if self.subcon:
                    sub_stream = io.BytesIO(match.group())
                    return self.subcon._parsereport(sub_stream, context, path)
                else:
                    return match.group()

            # Otherwise, we are going to parse each named capture group.
            obj = Container()
            obj._io = stream

            context = Container(_=context, _params=context._params, _root=None, _parsing=context._parsing,
                                _building=context._building, _sizing=context._sizing, _subcons=self.group_subcons,
                                _io=stream, _index=context.get("_index", None))
            context._root = context._.get("_root", context)

            # Default to displaying matched data as pure bytes.
            obj.update(group_dict)
            context.update(group_dict)

            # Parse groups using supplied constructs.
            for name, subcon in self.group_subcons.items():
                try:
                    data = match.group(name)
                except IndexError:
                    continue

                # If data is None, then we are most likely dealing with an optional capture group.
                if data is None:
                    obj[name] = None
                    context[name] = None
                    continue

                # If we have an empty capture group, the user would like to use it as an anchor.
                if not data:
                    stream.seek(start + match.start(name))
                    sub_stream = stream
                else:
                    sub_stream = io.BytesIO(data)

                try:
                    subobj = subcon._parsereport(sub_stream, context, path)
                except ConstructError as e:
                    # Raise a more useful error message.
                    # TODO: Remove when path is provided in exception messages.
                    raise ConstructError('Failed to parse {} capture group with error: {}'.format(name, e))
                obj[name] = subobj
                context[name] = subobj
            return obj

        finally:
            # Reset position to right after the matched regex.
            stream.seek(start + match.end())

    def _build(self, obj, stream, context, path):
        raise ConstructError('Building for Regex is not supported.')

    def _sizeof(self, context, path):
        raise SizeofError('sizeof() for Regex is not supported.')

    def _emitparse(self, code):
        raise NotImplementedError

    def _emitseq(self, ksy, bitwise):
        raise NotImplementedError


class IterError(ConstructError):
    pass


# TODO: Should this be renamed to Map?
class Iter(Construct):
    r"""
    Class that allows iterating over an object and acting on each item.

    e.g.
    >>> spec = Struct(
    ...     'types' / Byte[3],
    ...     'entries' / Iter(this.types, {
    ...        1: construct.Int32ul,
    ...        2: construct.Int16ul,
    ...     },
    ...     default=construct.Pass
    ...     )
    ... )
    >>> spec.parse('\x01\x02\x09\x03\x03\x03\x03\x06\x06')
    Container(types=ListContainer([1, 2, 9]), entries=ListContainer([50529027, 1542, None]))
    >>> C = _
    >>> spec.build(C)
    '\x01\x02\t\x03\x03\x03\x03\x06\x06'
    >>> spec.sizeof(**C)
    9

    >>> spec = Struct(
    ...     'sizes' / Int16ul[4],
    ...     'entries' / Iter(this.sizes, Bytes)  # equivalent to Iter(this.sizes, lambda size: Bytes(size))
    ... )
    >>> spec.parse('\x01\x00\x03\x00\x00\x00\x05\x00abbbddddd')
    Container(sizes=ListContainer([1, 3, 0, 5]), entries=ListContainer(['a', 'bbb', '', 'ddddd']))
    >>> C = _
    >>> spec.build(C)
    '\x01\x00\x03\x00\x00\x00\x05\x00abbbddddd'
    >>> Iter(this.sizes, Bytes).sizeof(sizes=[1,2,3,0])
    6
    >>> spec.sizeof(**C)
    17

    :param iterable: iterable items to act upon
    :param cases: A dictionary of cases or a function that takes takes a key and returns a construct spec.
    :param default: The default case (only if cases is a dict)
    """
    __slots__ = ['iterable', 'cases', 'default']
    
    def __init__(self, iterable, cases, default=None):
        super(Iter, self).__init__()
        self.iterable = iterable
        self.cases = cases
        self.default = default or Pass
        if not callable(cases):
            self.flagbuildnone = all(sc.flagbuildnone for sc in cases.values())
            self.flagembedded = all(sc.flagembedded for sc in cases.values())
        
    def _parse(self, stream, context, path):
        iterator = iter(self.iterable(context)) if callable(self.iterable) else iter(self.iterable)
        if callable(self.cases):
            return ListContainer([self.cases(key)._parsereport(stream, context, path) for key in iterator])
        else:
            return ListContainer([self.cases.get(key, self.default)._parsereport(stream, context, path) for key in iterator])
        
    def _build(self, obj, stream, context, path):
        iterator = iter(self.iterable(context)) if callable(self.iterable) else iter(self.iterable)
        for sub_obj, key in zip(obj, iterator):
            if callable(self.cases):
                self.cases(key)._build(sub_obj, stream, context, path)
            else:
                self.cases.get(key, self.default)._build(sub_obj, stream, context, path)
            
    def _sizeof(self, context, path):
        iterator = iter(evaluate(self.iterable, context))
        size = 0
        for key in iterator:
            try:
                if callable(self.cases):
                    size += self.cases(key)._sizeof(context, path)
                else:
                    size += self.cases.get(key, self.default)._sizeof(context, path)
            except (KeyError, AttributeError):
                raise SizeofError("cannot calculate size, {!r} key not found in context".format(key))
        return size


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
    [(3L, Container(int=10, string=u'hello')), (15L, Container(int=11, string=u'world'))]
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
        except (construct.ConstructError, OverflowError) as e:
            data.seek(offset + 1)
        else:
            yield offset, data_element

        # Test if we hit end of data.
        if data.read(1):
            data.seek(-1, os.SEEK_CUR)
        else:
            break


class Backwards(Subconstruct):
    r"""
    Subconstruct used to parse a given subconstruct backwards in the stream.
    This ia a macro for seeking backwards before parsing the construct.
    (This will not work for subcons that don't have a valid sizeof.
    Except for GreedyBytes and GreedyString)

    The stream will be left off at the start of the parsed result by design.
    Therefore, doing something like Int32ul >> Backwards(Int32ul) >> Int32ul will parse
    the same data 3 times.

    e.g.
    >>> (Bytes(14) >> Backwards(Int32ul) >> Tell).parse(b'junk stuff\x01\x02\x00\x00')
    ListContainer(['junk stuff\x01\x02\x00\x00', 513, 10L])
    >>> spec = Struct(Seek(0, os.SEEK_END), 'name' / Backwards(String(9)), 'number' / Backwards(Int32ul))
    >>> spec.parse(b'A BUNCH OF JUNK DATA\x01\x00\x00\x00joe shmoe')
    Container(name=u'joe shmoe', number=1)

    WARNING: This will break if the subcon doesn't have a valid sizeof.
    >>> spec = Struct(Seek(0, os.SEEK_END), 'name' / Backwards(CString()), 'number' / Backwards(Int32ul))
    >>> spec.parse(b'A BUNCH OF JUNK DATA\x01\x00\x00\x00joe shmoe\x00')
    Traceback (most recent call last):
      ...
    SizeofError

    However, GreedyBytes and GreedyString are allowed.
    >>> spec = Struct(Seek(0, os.SEEK_END), 'name' / Backwards(String(9)), 'rest' / Backwards(GreedyBytes))
    >>> spec.parse(b'A BUNCH OF JUNK DATA\x01\x00\x00\x00joe shmoe')
    Container(name=u'joe shmoe', rest=b'A BUNCH OF JUNK DATA\x01\x00\x00\x00')
    >>> spec = Struct(Seek(0, os.SEEK_END), 'name' / Backwards(String(9)), 'rest' / Backwards(GreedyString(encoding='utf-16-le')))
    >>> spec.parse(b'h\x00e\x00l\x00l\x00o\x00joe shmoe')
    Container(name=u'joe shmoe', rest=u'hello')

    WARNING: This will also break if you read more data that is behind the current position.
    >>> (Seek(0, os.SEEK_END) >> Backwards(String(10))).parse('yo')
    Traceback (most recent call last):
      ...
    FormatFieldError: could not read enough bytes, expected 10, found 2
    """
    __slots__ = ['greedy']

    def __init__(self, subcon):
        super(Backwards, self).__init__(subcon)
        # GreedyBytes and GreedyString are allowed special cases.
        self.greedy = self.subcon is GreedyBytes or (
                isinstance(self.subcon, construct.StringEncoded) and self.subcon.subcon is GreedyBytes)

    def _parse(self, stream, context, path):
        # Seek back to start of subcon.
        orig_pos = stream.tell()
        if self.greedy:
            start_pos = stream.seek(0)
            size = orig_pos - start_pos
            try:
                sub_stream = io.BytesIO(stream_read(stream, size))
                return self.subcon._parsereport(sub_stream, context, path)
            finally:
                stream.seek(start_pos)
        else:
            size = self.subcon._sizeof(context, path)
            start_pos = stream.seek(size * -1, os.SEEK_CUR)
            # Determine if we fell off the front.
            if orig_pos - start_pos < size:
                raise FormatFieldError("could not read enough bytes, expected %d, found %d" % (size, orig_pos - start_pos))
            try:
                return self.subcon._parsereport(stream, context, path)
            finally:
                stream.seek(start_pos)

    def _build(self, obj, stream, context, path):
        # TODO: Add support for building.
        raise NotImplementedError('Building is not supported.')


# Monkey patch RawCopy so that it can handle when we read the stream backwards.
def _parse(self, stream, context, path):
    offset1 = stream.tell()
    obj = self.subcon._parsereport(stream, context, path)
    offset2 = stream.tell()
    # Swap if subcon read backwards.
    if offset1 > offset2:
        offset1, offset2 = offset2, offset1
    fallback = stream.tell()
    stream_seek(stream, offset1)
    data = stream_read(stream, offset2-offset1)
    stream.seek(fallback)
    return Container(data=data, value=obj, offset1=offset1, offset2=offset2, length=(offset2-offset1))


construct.RawCopy._parse = _parse


def FocusLast(*subcons, **kw):
    r"""
    A helper for performing the common technique of using FocusedSeq to
    parse a bunch of subconstructs and then grab the last element.

    >>> FocusLast(Byte, Byte, String(2)).parse(b'\x01\x02hi')
    u'hi'

    >>> spec = FocusLast(
    ...     'a' / Byte,
    ...     'b' / Byte,
    ...     String(this.a + this.b),
    ... )
    >>> spec.parse(b'\x01\x02hi!')
    u'hi!'
    >>> spec.build(u'hi!', a=1, b=2)
    '\x01\x02hi!'


    e.g.:
        # Simplifies this:
        construct.FocusedSeq(
            'value',
            're' / construct.Regex(.., offset=construct.Int32ul, size=construct.Byte),
            'value' / construct.PEPointer(this.re.offset, construct.Bytes(this.re.size)
        )
        # To this:
        construct.FocusLast(
            're' / construct.Regex(.., offset=construct.Int32ul, size=construct.Byte),
            construct.PEPointer(this.re.offset, construct.Bytes(this.re.size)
        )
    """
    return FocusedSeq(len(subcons) - 1, *subcons, **kw)
