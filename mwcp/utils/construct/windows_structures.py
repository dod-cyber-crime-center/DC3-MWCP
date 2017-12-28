"""
A central location to store common windows enumerations.
This module will be imported along with 'from mwcp.utils import construct'
"""

import construct
from construct import *
from . import helpers

"""PEFILE STRUCTURES"""

IMAGE_DOS_HEADER = construct.Struct(
    "e_magic" / construct.String(2),
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

IMAGE_FILE_HEADER = construct.Struct(
    "Machine" / construct.Int16ul,
    "NumberOfSections" / construct.Int16ul,
    "TimeDateStamp" / construct.Int32ul,
    "PointerToSymbolTable" / construct.Int32ul,
    "NumberOfSymbols" / construct.Int32ul,
    "SizeOfOptionalHeader" / construct.Int16ul,
    "Characteristics" / construct.Int32ul
)

IMAGE_OPTIONAL_HEADER = construct.Struct(
    "Magic" / construct.Int16ul,
    "MajorLinkerVersion" / construct.Byte,
    "MinorLinkerVersion" / construct.Byte,
    "SizeOfCode" / construct.Int32ul,
    "SizeOfInitializedData" / construct.Int32ul,
    "SizeOfUninitializedData" / construct.Int32ul,
    "AddressOfEntryPoint" / construct.Int32ul,
    "BaseOfCode" / construct.Int32ul,
    "BaseOfData" / construct.Int32ul,
    "ImageBase" / construct.Int32ul,
    "SectionAlignment" / construct.Int32ul,
    "FileAlignment" / construct.Int32ul,
    "MajorOperatingSystemVersion" / construct.Int16ul,
    "MinorOperatingSystemVersion" / construct.Int16ul,
    "MajorImageVersion" / construct.Int16ul,
    "MinorImageVersion" / construct.Int16ul,
    "MajorSubsystemVersion" / construct.Int16ul,
    "MinorSubsystemVersion" / construct.Int16ul,
    "Win32VersionValue" / construct.Int32ul,
    "SizeOfImage" / construct.Int32ul,
    "SizeOfHeaders" / construct.Int32ul,
    "CheckSum" / construct.Int32ul,
    "Subsystem" / construct.Int16ul,
    "DllCharacteristics" / construct.Int16ul,
    "SizeOfStackReserve" / construct.Int32ul,
    "SizeOfStackCommit" / construct.Int32ul,
    "SizeOfHeapReserve" / construct.Int32ul,
    "SizeOfHeapCommit" / construct.Int32ul,
    "LoaderFlags" / construct.Int32ul,
    "NumberOfRvaAndSizes" / construct.Int32ul,
)

IMAGE_NT_HEADERS = construct.Struct(
    "Signature" / construct.Int32ul,
    "FileHeader" / IMAGE_FILE_HEADER,
    "OptionalHeader" / IMAGE_OPTIONAL_HEADER
)

PEFILE_HEADER = construct.Struct(
    "DosHeader" / IMAGE_DOS_HEADER,
    construct.Seek(this.DosHeader.e_lfanew),
    "NTHeaders" / IMAGE_NT_HEADERS
)

"""WINSOCK STRUCTURES"""

SOCKADDR_IN = construct.Struct(
    "sin_family" / construct.Int16ul,
    "sin_port" / construct.Int16ub,
    "sin_addr" / helpers.IP4Address,
    "sin_zero" / construct.Bytes(8)
)
