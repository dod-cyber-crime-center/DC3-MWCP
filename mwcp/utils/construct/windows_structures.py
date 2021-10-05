"""
A central location to store common windows enumerations.
This module will be imported along with 'from mwcp.utils import construct'
"""

from __future__ import absolute_import, division

import datetime

from . import version28 as construct
from .version28 import this, len_

from . import network, datetime_, windows_enums
from .windows_constants import *


"""PEFILE STRUCTURES"""

IMAGE_DOS_HEADER = construct.Struct(
    "e_magic" / construct.Default(construct.Bytes(2), b"MZ"),
    "e_cblp" / construct.Int16ul,
    "e_cp" / construct.Int16ul,
    "e_crlc" / construct.Int16ul,
    "e_cparhdr" / construct.Int16ul,
    "e_mimalloc" / construct.Int16ul,
    "e_maxalloc" / construct.Int16ul,
    "e_ss" / construct.Int16ul,
    "e_sp" / construct.Int16ul,
    "e_csum" / construct.Int16ul,
    "e_ip" / construct.Int16ul,
    "e_cs" / construct.Int16ul,
    "e_lfarlc" / construct.Int16ul,
    "e_ovno" / construct.Int16ul,
    "e_res1" / construct.Bytes(8),
    "e_oemid" / construct.Int16ul,
    "e_oeminfo" / construct.Int16ul,
    "e_res2" / construct.Bytes(20),
    "e_lfanew" / construct.Int32ul
)


IMAGE_SECTION_HEADER = construct.Struct(
    "Name" / construct.String(8),
    "VirtualSize" / construct.Int32ul,  # alias "PhysicalAddress"
    "VirtualAddress" / construct.Int32ul,
    "SizeOfRawData" / construct.Int32ul,
    "PointerToRawData" / construct.Int32ul,
    "PointerToRelocations" / construct.Default(construct.Int32ul, 0),
    "PointerToLinenumbers" / construct.Default(construct.Int32ul, 0),
    "NumberOfRelocations" / construct.Default(construct.Int16ul, 0),
    "NumberOfLinenumbers" / construct.Default(construct.Int16ul, 0),
    "Characteristics" / construct.FlagsEnum(
        construct.Int32ul,
        IMAGE_SCN_TYPE_NO_PAD=0x00000008,
        IMAGE_SCN_CNT_CODE=0x00000020,
        IMAGE_SCN_CNT_INITIALIZED_DATA=0x00000040,
        IMAGE_SCN_CNT_UNINITIALIZED_DATA=0x00000080,
        IMAGE_SCN_LNK_OTHER=0x00000100,
        IMAGE_SCN_LNK_INFO=0x00000200,
        IMAGE_SCN_LNK_REMOVE=0x00000800,
        IMAGE_SCN_LNK_COMDAT=0x00001000,
        IMAGE_SCN_NO_DEFER_SPEC_EXC=0x00004000,
        IMAGE_SCN_GPREL=0x00008000,
        IMAGE_SCN_MEM_PURGEABLE=0x00020000,
        IMAGE_SCN_MEM_LOCKED=0x00040000,
        IMAGE_SCN_MEM_PRELOAD=0x00080000,
        IMAGE_SCN_ALIGN_1BYTES=0x00100000,
        IMAGE_SCN_ALIGN_2BYTES=0x00200000,
        IMAGE_SCN_ALIGN_4BYTES=0x00300000,
        IMAGE_SCN_ALIGN_8BYTES=0x00400000,
        IMAGE_SCN_ALIGN_16BYTES=0x00500000,
        IMAGE_SCN_ALIGN_32BYTES=0x00600000,
        IMAGE_SCN_ALIGN_64BYTES=0x00700000,
        IMAGE_SCN_ALIGN_128BYTES=0x00800000,
        IMAGE_SCN_ALIGN_256BYTES=0x00900000,
        IMAGE_SCN_ALIGN_512BYTES=0x00A00000,
        IMAGE_SCN_ALIGN_1024BYTES=0x00B00000,
        IMAGE_SCN_ALIGN_2048BYTES=0x00C00000,
        IMAGE_SCN_ALIGN_4096BYTES=0x00D00000,
        IMAGE_SCN_ALIGN_8192BYTES=0x00E00000,
        IMAGE_SCN_LNK_NRELOC_OVFL=0x01000000,
        IMAGE_SCN_MEM_DISCARDABLE=0x02000000,
        IMAGE_SCN_MEM_NOT_CACHED=0x04000000,
        IMAGE_SCN_MEM_NOT_PAGED=0x08000000,
        IMAGE_SCN_MEM_SHARED=0x10000000,
        IMAGE_SCN_MEM_EXECUTE=0x20000000,
        IMAGE_SCN_MEM_READ=0x40000000,
        IMAGE_SCN_MEM_WRITE=0x80000000,
    )
)

IMAGE_DATA_DIRECTORY = construct.Struct(
    "VirtualAddress" / construct.Int32ul,
    "Size" / construct.Int32ul,
)

IMAGE_EXPORT_DIRECTORY = construct.Struct(
    "Characteristics" / construct.Default(construct.Int32ul, 0),
    "TimeDateStamp" / datetime_.EpochTime,
    "MajorVersion" / construct.Int16ul,
    "MinorVersion" / construct.Int16ul,
    "Name" / construct.Int32ul,  # rva pointer to the name
    "Base" / construct.Int32ul,
    "NumberOfFunctions" / construct.Int32ul,
    "NumberOfNames" / construct.Int32ul,
    "AddressOfFunctions" / construct.Int32ul,
    "AddressOfNames" / construct.Int32ul,
    "AddressOfNameOrdinals" / construct.Int32ul,
)

IMAGE_IMPORT_DESCRIPTOR = construct.Struct(
    "Characteristics" / construct.Int32ul,
    "TimeDateStamp" / construct.Int32ul,
    "ForwarderChain" / construct.Int32ul,
    "Name" / construct.Int32ul,  # rva pointer to the name
    "FirstThunk" / construct.Int32ul,
)

IMAGE_OPTIONAL_HEADER = construct.Struct(
    "Magic" / construct.OneOf(construct.Int16ul, [
        IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_ROM_OPTIONAL_HDR_MAGIC]),
    "MajorLinkerVersion" / construct.Byte,
    "MinorLinkerVersion" / construct.Byte,
    "SizeOfCode" / construct.Int32ul,
    "SizeOfInitializedData" / construct.Int32ul,
    "SizeOfUninitializedData" / construct.Int32ul,
    "AddressOfEntryPoint" / construct.Int32ul,
    "BaseOfCode" / construct.Int32ul,
    "BaseOfData" / construct.If(this.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC, construct.Int32ul),
    "ImageBase" / construct.IfThenElse(
        this.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, construct.Int64ul, construct.Int32ul
    ),
    "SectionAlignment" / construct.Int32ul,
    "FileAlignment" / construct.Int32ul,
    "MajorOperatingSystemVersion" / construct.Int16ul,
    "MinorOperatingSystemVersion" / construct.Int16ul,
    "MajorImageVersion" / construct.Int16ul,
    "MinorImageVersion" / construct.Int16ul,
    "MajorSubsystemVersion" / construct.Int16ul,
    "MinorSubsystemVersion" / construct.Int16ul,
    "Win32VersionValue" / construct.Default(construct.Int32ul, 0),  # must be 0
    "SizeOfImage" / construct.Int32ul,
    "SizeOfHeaders" / construct.Int32ul,
    "CheckSum" / construct.Int32ul,
    # TODO: Use enums instead?
    "Subsystem" / construct.OneOf(construct.Int16ul, [
        IMAGE_SUBSYSTEM_UNKNOWN,
        IMAGE_SUBSYSTEM_NATIVE,
        IMAGE_SUBSYSTEM_WINDOWS_GUI,
        IMAGE_SUBSYSTEM_WINDOWS_CUI,
        IMAGE_SUBSYSTEM_OS2_CUI,
        IMAGE_SUBSYSTEM_POSIX_CUI,
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,
        IMAGE_SUBSYSTEM_EFI_APPLICATION,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
        IMAGE_SUBSYSTEM_EFI_ROM,
        IMAGE_SUBSYSTEM_XBOX,
        IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
    ]),
    "DllCharacteristics" / construct.FlagsEnum(
        construct.Int16ul,
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA=0x0020,
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE=0x0040,
        IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY=0x0080,
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT=0x0100,
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION=0x0200,
        IMAGE_DLLCHARACTERISTICS_NO_SEH=0x0400,
        IMAGE_DLLCHARACTERISTICS_NO_BIND=0x0800,
        IMAGE_DLLCHARACTERISTICS_APPCONTAINER=0x1000,
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER=0x2000,
        IMAGE_DLLCHARACTERISTICS_GUARD_CF=0x4000,
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE=0x8000,
    ),
    "SizeOfStackReserve" / construct.IfThenElse(
        this.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, construct.Int64ul, construct.Int32ul
    ),
    "SizeOfStackCommit" / construct.IfThenElse(
        this.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, construct.Int64ul, construct.Int32ul
    ),
    "SizeOfHeapReserve" / construct.IfThenElse(
        this.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, construct.Int64ul, construct.Int32ul
    ),
    "SizeOfHeapCommit" / construct.IfThenElse(
        this.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, construct.Int64ul, construct.Int32ul
    ),
    "LoaderFlags" / construct.Int32ul,
    "NumberOfRvaAndSizes" / construct.Rebuild(construct.Int32ul, construct.len_(this.DataDirectory)),
    "DataDirectory" / construct.Default(IMAGE_DATA_DIRECTORY[this.NumberOfRvaAndSizes], DEFAULT_DATA_DIRECTORIES[:]),
)

IMAGE_FILE_HEADER = construct.Struct(
    "Machine" / construct.Int16ul,  # IMAGE_FILE_MACHINE_*
    "NumberOfSections" / construct.Int16ul,
    "TimeDateStamp" / construct.Int32ul,
    "PointerToSymbolTable" / construct.Default(construct.Int32ul, 0),
    "NumberOfSymbols" / construct.Default(construct.Int32ul, 0),
    # NOTE: This defaults to assuming a 32-bit PE when building if the SizeOfOptionalHeader isn't provided in the context.
    "SizeOfOptionalHeader" / construct.Default(
        construct.Int16ul, IMAGE_OPTIONAL_HEADER.sizeof(Magic=IMAGE_NT_OPTIONAL_HDR32_MAGIC, NumberOfRvaAndSizes=16)),
    "Characteristics" / construct.FlagsEnum(
        construct.Int16ul,
        IMAGE_FILE_RELOCS_STRIPPED=0x0001,
        IMAGE_FILE_EXECUTABLE_IMAGE=0x0002,
        IMAGE_FILE_LINE_NUMS_STRIPPED=0x0004,
        IMAGE_FILE_LOCAL_SYMS_STRIPPED=0x0008,
        IMAGE_FILE_AGGRESIVE_WS_TRIM=0x0010,
        IMAGE_FILE_LARGE_ADDRESS_AWARE=0x0020,
        IMAGE_FILE_BYTES_REVERSED_LO=0x0080,
        IMAGE_FILE_32BIT_MACHINE=0x0100,
        IMAGE_FILE_DEBUG_STRIPPED=0x0200,
        IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP=0x0400,
        IMAGE_FILE_NET_RUN_FROM_SWAP=0x0800,
        IMAGE_FILE_SYSTEM=0x1000,
        IMAGE_FILE_DLL=0x2000,
        IMAGE_FILE_UP_SYSTEM_ONLY=0x4000,
        IMAGE_FILE_BYTES_REVERSED_HI=0x8000,
    ),
)

IMAGE_NT_HEADERS = construct.Struct(
    "Signature" / construct.Default(construct.Int32ul, 0x4550),  # b'PE\x00\x00'
    "FileHeader" / IMAGE_FILE_HEADER,
    "OptionalHeader" / IMAGE_OPTIONAL_HEADER
)

PEFILE_HEADER = construct.Struct(
    "DosHeader" / IMAGE_DOS_HEADER,
    # TODO: Use construct.FixedSized() if we ever update construct.
    "DosStub" / construct.Bytes(this.DosHeader.e_lfanew - IMAGE_DOS_HEADER.sizeof()),
    "NTHeaders" / IMAGE_NT_HEADERS,
    "SectionTable" / IMAGE_SECTION_HEADER[this.NTHeaders.FileHeader.NumberOfSections],
)

"""WINSOCK STRUCTURES"""

SOCKADDR_IN = construct.Struct(
    "sin_family" / construct.Int16ul,
    "sin_port" / construct.Int16ub,  # in network byte order
    "sin_addr" / network.IP4Address,
    "sin_zero" / construct.Bytes(8)
)

# Same as SOCKADDR_IN but with the port as little endian.
SOCKADDR_IN_L = construct.Struct(
    "sin_family" / construct.Int16ul,
    "sin_port" / construct.Int16ul,
    "sin_addr" / network.IP4Address,
    "sin_zero" / construct.Bytes(8)
)

"""CRYPTO STRUCTURES"""

PUBLICKEYSTRUC = construct.Struct(
    "type" / construct.Byte,
    "version" / construct.Byte,
    "reserved" / construct.Int16ul,
    "algid" / windows_enums.AlgorithmID(construct.Int32ul),
)

PUBLICKEYBLOB = construct.Struct(
    "publickeystruc" / PUBLICKEYSTRUC,
    construct.Check(this.publickeystruc.algid == "CALG_RSA_KEYX"),
    construct.Const(b"RSA1"),
    "bitlen" / construct.Int32ul,
    construct.Check((this.bitlen % 8) == 0),
    "pubexponent" / construct.Int32ul,
    "modulus" / construct.BytesInteger(this.bitlen // 8, swapped=True)
)

PRIVATEKEYBLOB = construct.Struct(
    "publickeystruc" / PUBLICKEYSTRUC,
    construct.Check(this.publickeystruc.algid == "CALG_RSA_KEYX"),
    construct.Const(b"RSA2"),
    "bitlen" / construct.Int32ul,
    construct.Check((this.bitlen % 8) == 0),
    "pubexponent" / construct.Int32ul,
    "modulus" / construct.BytesInteger(this.bitlen // 8, swapped=True),
    "P" / construct.BytesInteger(this.bitlen // 16, swapped=True),
    "Q" / construct.BytesInteger(this.bitlen // 16, swapped=True),
    # d % (p - 1)
    "Dp" / construct.BytesInteger(this.bitlen // 16, swapped=True),
    # d % (q - 1)
    "Dq" / construct.BytesInteger(this.bitlen // 16, swapped=True),
    # ~(q % p)
    "Iq" / construct.BytesInteger(this.bitlen // 16, swapped=True),
    # Private Exponent
    "D" / construct.BytesInteger(this.bitlen // 8, swapped=True)
)

"""TIME STRUCTURES"""

SYSTEMTIME = construct.Struct(
    "wYear" / construct.Int16ul,
    "wMonth" / construct.Int16ul,
    "wDayOfWeek" / construct.Int16ul,
    "wDay" / construct.Int16ul,
    "wHour" / construct.Int16ul,
    "wMinute" / construct.Int16ul,
    "wSecond" / construct.Int16ul,
    "wMilliseconds" / construct.Int16ul,
)


# TODO: Implement _encode
class SystemTimeAdapter(construct.Adapter):
    r"""
    Adapter to convert SYSTEMTIME structured data to datetime.datetime ISO format.

    >>> SystemTimeAdapter(SYSTEMTIME).parse(b'\xdd\x07\t\x00\x03\x00\x12\x00\t\x00.\x00\x15\x00\xf2\x02')
    '2013-09-18T09:46:21.754000'
    >>> SystemTimeAdapter(SYSTEMTIME, tzinfo=datetime.timezone.utc).parse(b'\xdd\x07\t\x00\x03\x00\x12\x00\t\x00.\x00\x15\x00\xf2\x02')
    '2013-09-18T09:46:21.754000+00:00
    """
    def __init__(self, subcon, tzinfo=None):
        """
        :param tzinfo: Optional timezone object, default is localtime
        :param subcon: subcon to parse SystemTime
        """
        super(SystemTimeAdapter, self).__init__(subcon)
        self._tzinfo = tzinfo

    def _decode(self, obj, context, path):
        return datetime.datetime(
            obj.wYear, obj.wMonth, obj.wDay, obj.wHour, obj.wMinute, obj.wSecond, obj.wMilliseconds * 1000,
            tzinfo=self._tzinfo
        ).isoformat()


# Add common helpers
SystemTime = SystemTimeAdapter(SYSTEMTIME)
SystemTimeUTC = SystemTimeAdapter(SYSTEMTIME, tzinfo=datetime.timezone.utc)


EPOCH_AS_FILETIME = 116444736000000000
HUNDREDS_OF_NANOSECONDS = 10000000


# TODO: Implement _encode
class FileTimeAdapter(construct.Adapter):
    r"""
    Adapter to convert FILETIME structured data to datetime.datetime ISO format.
    Technically FILETIME is two 32-bit integers as dwLowDateTime and dwHighDateTime, but there is no need to do that

    >>> FileTimeAdapter(construct.Int64ul).parse(b'\x00\x93\xcc\x11\xa7\x88\xd0\x01')
    '2015-05-07T05:20:33'
    >>> FileTimeAdapter(construct.Int64ul, tz=datetime.timezone.utc).parse(b'\x00\x93\xcc\x11\xa7\x88\xd0\x01')
    '2015-05-07T09:20:33.328000+00:00'
    """
    def __init__(self, subcon, tz=None):
        """
        :param tz: Optional timezone object, default is localtime
        :param subcon: subcon to parse FileTime
        """
        super(FileTimeAdapter, self).__init__(subcon)
        self._tz = tz

    def _decode(self, obj, context, path):
        return datetime.datetime.fromtimestamp(
            (obj - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS, tz=self._tz
        ).isoformat()


# Add common helpers
FileTime = FileTimeAdapter(construct.Int64ul)
FileTimeUTC = FileTimeAdapter(construct.Int64ul, tz=datetime.timezone.utc)
