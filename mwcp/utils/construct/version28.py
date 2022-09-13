"""
Collection of patches done to bring back some of the removed features of 2.8 back into 2.9
as well as generally fix lingering issues with construct.

To activate, replace your standard import with this:
    from mwcp.utils.construct import version28 as construct

Patches:
    - slicing mechanism ([:], [min:], [:max], etc)
    - allows default value for pop() in Containers
    - allow any encoding for string constructs.
    - patch Embedded to remove hardcoded limitation of supported classes.
    - fixes issue with sizeof used with dynamic Structs (issue #771)
    - patch StringEncoded to make UnicodeDecodeErrors as StringError (issue #743)

Also contains fixes for few constructs. (Use these versions to get the benefits.)
    - Range() - was removed in 2.9
    - PaddedString() - provides default encoding of 'utf-8' and fixes limitation on encoding codecs
    - String() - alias to PaddedString
    - GreedyString - default encoding to 'utf-8'
    - Compressed() - add ability to provide any algorithm (provided it has a compress() and decompress() function)
    - Union() - Allows for the parsefrom parameter to be optional.
    - Probe() - changed to show lookahead stream by default since that is almost always preferred.
              - Also converted back to use hexdump instead of just showing a hex string.
    - FocusedSeq() - Adds back support for supplying an index and fixes building.
    - Mapping() - Patches Mapping to allow non-symmetric mappings again.


Wishlist: (the following are things we would like to fix in version 2.9 but are out of scope for now)
    - Go back to merging embedded fields after parsing instead of before. This change breaks the ability
        to embed any Construct type. (e.g. Regex)
    - PaddedString() should allow providing a different padding character.
    - NullStripped() should not be a subconstruct that reads the entire stream instead it should be an
        Adapter that strips off the wrapped result.
    - Redefine String() to be the non-padded version of PaddedString()
        - (This will break compatibility with 2.8 but it seems to make the most sense)
        - Alternatively, rename PaddedString() back to String() and provide an flag parameter to determine if
          null characters should be stripped.
    - Add the path to ConstructError exceptions. This will greatly help with debugging.
    - Add deepcopy functionality for Container classes.
    - Embedding should also embed the context.
        - Also, Embedded should just be a function that toggles flagembedded instead of being it's own class.
    - remove _io from resulting Container objects after a parse. Doesn't look to be used for anything.
"""

from __future__ import absolute_import

from future.builtins import bytes, str

import codecs
import collections.abc
import sys

import construct
import construct.core
import construct.debug
from construct import *
from construct.core import *


class Range(Subconstruct):
    r"""
    A homogenous array of elements. The array will iterate through between ``min`` to ``max`` times. If an exception occurs (EOF, validation error), the repeater exits cleanly. If less than ``min`` units have been successfully parsed, a RangeError is raised.

    .. seealso:: Analog :func:`~construct.core.GreedyRange` that parses until end of stream.

    .. note:: This object requires a seekable stream for parsing.

    :param min: the minimal count
    :param max: the maximal count
    :param subcon: the subcon to process individual elements

    Example::

        >>> Range(3, 5, Byte).build([1,2,3,4])
        '\x01\x02\x03\x04'
        >>> Range(3, 5, Byte).parse(_)
        ListContainer([1, 2, 3, 4])

        >>> Range(3, 5, Byte).build([1,2])
        Traceback (most recent call last):
            ...
        RangeError: expected from 3 to 5 elements, found 2
        >>> Range(3, 5, Byte).build([1,2,3,4,5,6])
        Traceback (most recent call last):
            ...
        RangeError: expected from 3 to 5 elements, found 6
    """
    __slots__ = ["min", "max"]

    def __init__(self, min, max, subcon):
        super(Range, self).__init__(subcon)
        self.min = min
        self.max = max

    def _parse(self, stream, context, path):
        min_ = evaluate(self.min, context)
        max_ = evaluate(self.max, context)
        if not 0 <= min_ <= max_ <= sys.maxsize:
            raise RangeError("[{}] unsane min {} and max {}".format(path, min_, max_))
        obj = ListContainer()
        try:
            i = 0
            while len(obj) < max_:
                context._index = i
                fallback = stream.tell()
                obj.append(self.subcon._parsereport(stream, context, path))
                if stream.tell() == fallback:
                    raise ExplicitError("[{}] Infinite loop detected.".format(path))
                i += 1
        except StopIteration:
            pass
        except ExplicitError:
            raise
        except Exception:  # TODO: catch ConstructError instead?
            if len(obj) < min_:
                raise RangeError("[{}] expected {} to {}, found {}".format(path, min_, max_, len(obj)))
            stream.seek(fallback)
        return obj

    def _build(self, obj, stream, context, path):
        min_ = evaluate(self.min, context)
        max_ = evaluate(self.max, context)
        if not 0 <= min_ <= max_ <= sys.maxsize:
            raise RangeError("[{}] unsane min {} and max {}".format(path, min_, max_))
        if not isinstance(obj, collections.abc.Sequence):
            raise RangeError("[{}] expected sequence type, found {}".format(path, type(obj)))
        if not min_ <= len(obj) <= max_:
            raise RangeError("[{}] expected from {} to {} elements, found {}".format(path, min_, max_, len(obj)))
        retlist = ListContainer()
        try:
            for i, subobj in enumerate(obj):
                context._index = i
                buildret = self.subcon._build(subobj, stream, context, path)
                retlist.append(buildret)
        except StopIteration:
            pass
        except ExplicitError:
            raise
        except Exception:
            if len(obj) < min_:
                raise RangeError("[{}] expected {} to {}, found {}".format(path, min_, max_, len(obj)))
            else:
                raise
        return retlist

    def _sizeof(self, context, path):
        # WARNING: possibly broken by StopIf
        try:
            min_ = evaluate(self.min, context)
            max_ = evaluate(self.max, context)
        except (KeyError, AttributeError):
            raise SizeofError("cannot calculate size, key not found in context")
        if min_ == max_:
            return min_ * self.subcon._sizeof(context, path)
        else:
            raise SizeofError("cannot calculate size")


def CString(encoding='utf-8'):
    r"""
    Adds default encoding option to CString().

    >>> CString().parse(b'hello\x00')
    u'hello'
    >>> CString().parse(b'hello\x00\xff\xff')
    u'hello'
    >>> CString(encoding='utf-16').parse(b'\xff\xfeh\x00e\x00l\x00l\x00o\x00\x00\x00')  # FFFE is BOM for utf-16-le
    u'hello'
    >>> CString(encoding='utf-16').parse(b'h\x00e\x00l\x00l\x00o\x00\x00\x00')
    u'hello'
    >>> CString(encoding='utf-16').build(u'hello')
    '\xff\xfeh\x00e\x00l\x00l\x00o\x00\x00\x00'
    >>> CString(encoding='utf-32').build(u'hello')
    '\xff\xfe\x00\x00h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00\x00\x00\x00\x00'

    Make sure to specify 'le' or 'be' in the encoding if you don't want BOM markers when building.
    >>> CString(encoding='utf-32-le').build(u'hello')
    'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00\x00\x00\x00\x00'
    >>> CString(encoding='utf-32-be').build(u'hello')
    '\x00\x00\x00h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00\x00'
    """
    return construct.CString(encoding)


def PaddedString(length, encoding='utf-8'):
    r"""
    Adds default encoding option to PaddedString().

    NOTE: When using this to build a multi-byte encoded string you need to be aware of the extra space that can be taken
    up by BOM markings when specifying the length.
    If you don't want BOM. Make sure to explicitly specify "le" or "be" at the end of your encoding.
    >>> u'hi'.encode('utf-16')
    '\xff\xfeh\x00i\x00'
    >>> u'hi'.encode('utf-16-le')
    'h\x00i\x00'

    :param length: length in bytes (not unicode characters), as int or context function
    :param encoding: encoding (e.g. "utf8") or None for bytes

    e.g.
    >>> StringEncoded(Bytes(10), 'utf-16').parse(b'h\x00e\x00l\x00l\x00o\x00')
    u'hello'
    >>> PaddedString(10, encoding='utf-16').parse(b'h\x00e\x00l\x00l\x00o\x00')
    u'hello'
    >>> PaddedString(12, encoding='utf-16').build(u'hello')
    '\xff\xfeh\x00e\x00l\x00l\x00o\x00'
    >>> PaddedString(10, encoding='utf-16le').build(u'hello')
    'h\x00e\x00l\x00l\x00o\x00'
    >>> PaddedString(16, encoding='utf-16le').build(u'hello')
    'h\x00e\x00l\x00l\x00o\x00\x00\x00\x00\x00\x00\x00'
    >>> PaddedString(16, encoding='utf-16').parse(b'h\x00e\x00l\x00l\x00o\x00\x00\x00\x00\x00\x00\x00')
    u'hello'

    Works with utf-32 in the same way.
    >>> PaddedString(20, encoding='utf-32-le').build(u'hello')
    'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00'
    >>> PaddedString(20, encoding='utf-32').parse(b'h\x00\x00\x00e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00')
    u'hello'

    Also, still works with regular single byte encodings.
    >>> PaddedString(5).build(u'hello')
    'hello'
    >>> PaddedString(5).parse(b'hello')
    u'hello'

    A StringError (type of ConstructError) will be raised if the string cannot be decoded with the given encoding.
    >>> PaddedString(8).parse(b'hello\x00\xff\xff')
    Traceback (most recent call last):
        ...
    StringError: string decoding failed: 'utf8' codec can't decode byte 0xff in position 6: invalid start byte
    """
    return construct.PaddedString(length, encoding)

# Alias for original 2.8 name
# FIXME: String() should not remove the null padding!
String = PaddedString


def GreedyString(encoding='utf-8'):
    """Adds default encoding option to PaddedString()."""
    return construct.GreedyString(encoding)


class Compressed(Adapter):
    r"""
    Replaces the original Compressed construct to improve functionality:
        - supports providing a custom encoding module or object.
            - (provide any object that has a "decompress" and "compress" function in the lib parameter.)
        - produces a ConstructError if compressed/decompression fails.
            - (You can turn this off by setting wrap_exception=False)
        - uses Adapter instead of Tunnel in order to allow it be embedded within other constructs.
            - (Original one read entire stream, no matter the subcon you provide.)

    e.g.
    >>> import zlib
    >>> Compressed(GreedyBytes, zlib).build('hello world')
    'x\x9c\xcbH\xcd\xc9\xc9W(\xcf/\xcaI\x01\x00\x1a\x0b\x04]'
    >>> Compressed(GreedyBytes, zlib).parse(_)
    'hello world'
    >>> import dc3cipher
    >>> lzma = dc3cipher.new('lzma')
    >>> Compressed(GreedyBytes, lzma).build('hello world')
    ']\x00\x00\x80\x00\x004\x19I\xee\x8d\xe9\x17\x89:3`\x05\xf7\xcfd\xff\xfbx \x00'
    >>> Compressed(GreedyBytes, lzma).parse(_)
    'hello world'

    Now that this is an Adapter, it can be become part of a larger struct.
    >>> spec = Struct(
    ...     'magic' / Const('YUP'),
    ...     'data' / Compressed(Bytes(26), lzma),
    ...     'trailer' / Int32ul,
    ... )
    >>> spec.parse('YUP]\x00\x00\x80\x00\x004\x19I\xee\x8d\xe9\x17\x89:3`\x05\xf7\xcfd\xff\xfbx \x00\x03\x00\x00\x00')
    Container(magic='YUP')(data='hello world')(trailer=3)
    >>> spec.build(_)
    'YUP]\x00\x00\x80\x00\x004\x19I\xee\x8d\xe9\x17\x89:3`\x05\xf7\xcfd\xff\xfbx \x00\x03\x00\x00\x00'
    """
    __slots__ = ["lib", "wrap_exception"]

    def __init__(self, subcon, lib, wrap_exception=True):
        super(Compressed, self).__init__(subcon)
        self.wrap_exception = wrap_exception
        if hasattr(lib, "compress") and hasattr(lib, "decompress"):
            self.lib = lib
        elif lib == "zlib":
            import zlib
            self.lib = zlib
        elif lib == "gzip":
            import gzip
            self.lib = gzip
        elif lib == "bzip2":
            import bz2
            self.lib = bz2
        else:
            raise ValueError('Invalid lib parameter: {}'.format(lib))

    def _decode(self, data, context, path):
        try:
            return self.lib.decompress(data)
        except Exception as e:
            if self.wrap_exception:
                raise ConstructError('Decompression failed with error: {}'.format(e))
            else:
                raise

    def _encode(self, data, context, path):
        try:
            return self.lib.compress(data)
        except Exception as e:
            if self.wrap_exception:
                raise ConstructError('Compression failed with error: {}'.format(e))
            else:
                raise


class Union(construct.Union):
    """
    Patches the Union() Construct to not require the parsefrom parameter. (defaults to None)
    """

    def __init__(self, parsefrom_or_subcon, *subcons, **subconskw):
        if isinstance(parsefrom_or_subcon, Construct):
            parsefrom = None
            subcons = (parsefrom_or_subcon,) + subcons
        else:
            parsefrom = parsefrom_or_subcon
        super(Union, self).__init__(parsefrom, *subcons, **subconskw)


# Map an integer in the inclusive range 0-255 to its string byte representation
PRINTABLE = [bytes2str(int2byte(i)) if 32 <= i < 128 else '.' for i in range(256)]
HEXPRINT = [format(i, '02X') for i in range(256)]

# Copy of construct.lib.hex.hexdump but removes the "hexundump(" string.
# Not sure why that was added....
def hexdump(data, linesize):
    r"""
    Turns bytes into a unicode string of the format:

    ::

        >>> print(hexdump(b'0' * 100, 16))
        hexundump(\"\"\"
        0000   30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30   0000000000000000
        0010   30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30   0000000000000000
        0020   30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30   0000000000000000
        0030   30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30   0000000000000000
        0040   30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30   0000000000000000
        0050   30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30   0000000000000000
        0060   30 30 30 30                                       0000
        \"\"\")
    """
    if len(data) < 16**4:
        fmt = "%%04X   %%-%ds   %%s" % (3*linesize-1,)
    elif len(data) < 16**8:
        fmt = "%%08X   %%-%ds   %%s" % (3*linesize-1,)
    else:
        raise ValueError("hexdump cannot process more than 16**8 or 4294967296 bytes")
    prettylines = []
    for i in range(0, len(data), linesize):
        line = data[i:i+linesize]
        hextext = " ".join(HEXPRINT[b] for b in iterateints(line))
        rawtext = "".join(PRINTABLE[b] for b in iterateints(line))
        prettylines.append(fmt % (i, str(hextext), str(rawtext)))
    return "\n".join(prettylines)


class Probe(construct.Probe):
    """
    Patches back some of the features of Probe() that were removed:

        - The lookahead stream is enabled by default
        - Use hexdump instead of hexlify to display lookahead stream
        - Allows for setting a name
    """
    def __init__(self, into=None, lookahead=128, name=None):
        self.print_name = name
        super(Probe, self).__init__(into=into, lookahead=lookahead)

    def printout(self, stream, context, path):
        print("--------------------------------------------------")
        print("Probe {}".format(self.print_name or ''))
        print("Path: {}".format(path))
        if self.into:
            print("Into: {!r}".format(self.into))

        if self.lookahead and stream is not None:
            fallback = stream.tell()
            stream_bytes = stream.read(self.lookahead)
            stream.seek(fallback)
            if stream_bytes:
                print("Stream peek:\n{}".format(hexdump(stream_bytes, 32)))
            else:
                print("Stream peek: EOF reached")

        if context is not None:
            if self.into:
                try:
                    subcontext = self.into(context)
                    print(subcontext)
                except Exception:
                    print("Failed to compute {!r} on the context {!r}".format(self.into, context))
            else:
                print(context)
        print("--------------------------------------------------")


class FocusedSeq(construct.FocusedSeq):
    """
    Patches FocusedSeq to add back support for supplying an index.

    Also fixes the build and parse functions.
    """

    def _parse(self, stream, context, path):
        context = Container(_ = context, _params = context._params, _root = None, _parsing = context._parsing, _building = context._building, _sizing = context._sizing, _subcons = self._subcons, _io = stream, _index = context.get("_index", None))
        context._root = context._.get("_root", context)
        parsebuildfrom = evaluate(self.parsebuildfrom, context)

        found = False  # Must use separate flag because returning a parse result of None is valid.
        finalret = None
        for i, sc in enumerate(self.subcons):
            parseret = sc._parsereport(stream, context, path)
            context[i] = parseret  # PATCH: re-added ability to reference by index.
            if sc.name:
                context[sc.name] = parseret
            if sc.name == parsebuildfrom or i == parsebuildfrom:
                finalret = parseret
                found = True

        if not found:
            raise ConstructError("Unable to find entry: {}".format(parsebuildfrom))

        return finalret

    def _build(self, obj, stream, context, path):
        context = Container(_ = context, _params = context._params, _root = None, _parsing = context._parsing, _building = context._building, _sizing = context._sizing, _subcons = self._subcons, _io = stream, _index = context.get("_index", None))
        context._root = context._.get("_root", context)
        parsebuildfrom = evaluate(self.parsebuildfrom, context)

        found = False
        finalret = None
        for i, sc in enumerate(self.subcons):
            if sc.name == parsebuildfrom or i == parsebuildfrom:
                sub_obj = obj
            else:
                sub_obj = context._.get(sc.name, context._.get(i, None))
            try:
                buildret = sc._build(sub_obj, stream, context, path)
            except ConstructError as e:
                raise ConstructError("Unable to build field at index: {}".format(i))

            context[i] = buildret
            if sc.name:
                context[sc.name] = buildret

            if sc.name == parsebuildfrom or i == parsebuildfrom:
                finalret = buildret
                found = True

        if not found:
            raise ConstructError("Unable to find entry: {}".format(parsebuildfrom))

        return finalret


class Mapping(construct.Mapping):
    r"""
    Patches Mapping to allow non-symmetric mappings by swapping the mapping
    from encoding (building) to decoding (parsing) and allow for an optional mapping in the other direction.

    :param subcon: Construct instance
    :param mapping: dict, for decoding (parsing) mapping
    :param enc_mapping: Optional mapping for encoding (building), otherwise the reversed decoding mapping it used

    Example::
        >>> spec = Mapping(Byte, {0: u'a', 1: u'b', 2: u'b'})
        >>> spec.parse(b'\x02')
        u'b'

        # Reverse mapping is sorted so 1 will be used instead of 2.
        >>> spec.build(u'b')
        '\x01'
    """

    def __init__(self, subcon, dec_mapping, enc_mapping=None):
        super(Mapping, self).__init__(subcon, {})
        self.decmapping = dec_mapping
        self.encmapping = enc_mapping or {v: k for k, v in sorted(dec_mapping.items(), reverse=True)}



def _patch_pop():
    """
    Patches the pop() function in Container to allow for a default value.
    """
    def pop(self, key, *default):
        try:
            val = dict.pop(self, key, *default)
            self.__keys_order__.remove(key)
            return val
        except ValueError:
            if default:
                return default[0]
            else:
                raise KeyError

    Container.pop = pop


def _patch_slice():
    """Patches the slicing mechanism to use Range"""
    orig_get_item = Construct.__getitem__

    def __getitem__(self, count):
        if isinstance(count, slice):
            if count.step is not None:
                raise ValueError("slice must not contain a step: %r" % count)
            min = 0 if count.start is None else count.start
            max = sys.maxsize if count.stop is None else count.stop
            return Range(min, max, self)
        else:
            return orig_get_item(self, count)

    Construct.__getitem__ = __getitem__


def _patch_StringEncoded():
    """
    Patches StringEncoded to throw a ConstructError type exception if decoding fails.

    Fixes: github.com/construct/construct/issues/743
    """
    orig_decode = construct.StringEncoded._decode

    def _decode(self, obj, context, path):
        try:
            return orig_decode(self, obj, context, path)
        except UnicodeDecodeError as e:
            raise StringError("[{}] string decoding failed: {}".format(path, e))

    construct.StringEncoded._decode = _decode


def _patch_sizeof():
    """
    Patches the sizeof() function in Struct, Sequence, and FocusedSeq to properly provide context.

    Fixes: github.com/construct/construct/issues/771
    """
    def _sizeof(self, context, path):
        # Removed the context manipulation.
        try:
            # Added back dereferencing nested context that was incorrectly removed.
            def isStruct(sc):
                return isStruct(sc.subcon) if isinstance(sc, Renamed) else isinstance(sc, Struct)
            def nest(context, sc):
                if isStruct(sc) and not sc.flagembedded and sc.name in context:
                    context2 = context[sc.name]
                    context2["_"] = context
                    return context2
                else:
                    return context
            return sum(sc._sizeof(nest(context, sc), path) for sc in self.subcons)
        except (KeyError, AttributeError):
            raise SizeofError("cannot calculate size, key not found in context")

    # Conveniently, all 3 Constructs are implemented in the same way.
    construct.Struct._sizeof = _sizeof
    construct.Sequence._sizeof = _sizeof
    construct.FocusedSeq._sizeof = _sizeof


def _patch_encodingunit():
    """
    Patches the encodingunit() function that is used to calculate
    sizes for null terminated strings.

    This fixes the limitation of having a hardcoded set of supported encodings found in the original
    implementation.
    """
    # must be ordered largest to smallest
    _BOM_BYTES = (
        codecs.BOM_UTF32_LE,
        codecs.BOM_UTF32_BE,
        codecs.BOM_UTF16_LE,
        codecs.BOM_UTF16_BE,
        codecs.BOM_UTF8,
    )

    # NOTE: We can't patch in our version of encodingunit() so we are going to have to reimplement
    # the functions that use it (seen below)
    def encodingunit(encoding):
        r"""
        >>> encodingunit('utf-8')
        b'\x00'
        >>> encodingunit('utf-16le')
        b'\x00\x00'
        >>> encodingunit('utf-16')
        b'\x00\x00'
        >>> encodingunit('utf-32')
        b'\x00\x00\x00\x00'
        >>> encodingunit('cp950')
        b'\x00'
        """
        # Check "basic" byte size without BOM mark
        encoding = encoding.lower()
        encoded = u'\0'.encode(encoding)
        for bom_bytes in _BOM_BYTES:
            if encoded.startswith(bom_bytes) and len(bom_bytes) < len(encoded):
                encoded = encoded[len(bom_bytes):]
                break
        return bytes(len(encoded))

    construct.core.encodingunit = encodingunit


def _patch_mergefields():
    """
    Patches the mergefields() function to remove the hardcoded list of embeddable classes.

    This fixes the issue of trying to wrap Embedded around a Bitwise component.

    Fixes: github.com/construct/construct/issues/TODO
    """
    def mergefields(*subcons):
        def select(sc):
            # If it quacks like a duck...
            if hasattr(sc, 'subcons'):
                return sc.subcons
            elif hasattr(sc, 'subcon'):
                return select(sc.subcon)
            raise ConstructError(
                "Embedding only works with: Struct Sequence FocusedSeq Union LazyStruct: {!r}".format(sc))

        result = []
        for sc in subcons:
            if sc.flagembedded:
                result.extend(select(sc))
            else:
                result.append(sc)
        return result

    construct.core.mergefields = mergefields


def _patch():
    """Patches 2.9 with 2.8 features and other general fixes."""
    _patch_pop()
    _patch_slice()
    _patch_StringEncoded()
    _patch_sizeof()
    _patch_encodingunit()
    _patch_mergefields()


_patch()
