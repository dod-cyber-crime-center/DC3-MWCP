"""
Utility for lief Macho-O implementation
"""

from __future__ import annotations
from functools import lru_cache
import lief
from typing import List, Iterable, Optional

from mwcp.utils import construct


@lru_cache()
def obtain_macho(file_data: bytes) -> Optional[lief.MachO.FatBinary]:
    """
    Obtain a Mach-O object for the given file object

    :param bytes file_data: Input Data

    :return: Mach-O object
    :rtype: lief.MachO.FatBinary
    """
    data = list(bytearray(file_data))
    if lief.is_macho(data):
        return lief.MachO.parse(data)


def get_cpu_type(macho: lief.MachO.FatBinary, index: int) -> str:
    """
    Obtain the cpu type for the binary at the provided index

    :param lief.MachO.FatBinary macho: Mach-O object
    :param int index: Index of target binary

    :return: Cpu type
    :rtype: str
    """
    return str(macho.at(index).header.cpu_type).split(".")[-1]


def obtain_section(section_name: str, macho: lief.MachO.FatBinary) -> Optional[lief.MachO.Section]:
    """
    Obtain the specified section for the macho

    :param str section_name: The name of the section to obtain
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: The Mach-O section
    :rtype: lief.MachO.Section
    """
    for idx in range(macho.size):
        macho_bin = macho.at(idx)
        for sec in macho_bin.sections:
            if sec.name == section_name:
                return sec


def obtain_section_data(section_name: str, macho: lief.MachO.FatBinary) -> Optional[bytes]:
    """
    Obtain the data in the specified section for the macho

    :param str section_name: The name of the section to obtain data for
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: Mach-O section
    :rtype: bytes
    """
    if sec := obtain_section(section_name, macho):
        return bytes(bytearray(sec.content))


def check_section(section_name: str, macho: lief.MachO.FatBinary) -> bool:
    """
    Check if the specified section is in the macho_obj

    :param str section_name: The name of the section to obtain
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: If the section is present
    :rtype: bool
    """
    return bool(obtain_section(section_name, macho))


def iter_symbols(macho: lief.MachO.FatBinary) -> Iterable[lief.MachO.Symbol]:
    """
    Iterate Mach-O object symbols

    :param lief.MachO.FatBinary macho: Mach-O object

    :yield: Mach-O object symbols
    """
    for idx in range(macho.size):
        macho_bin = macho.at(idx)
        yield from macho_bin.symbols


def iter_cstring_literals(macho: lief.MachO.FatBinary) -> Iterable[bytes]:
    """
    Iterate cstring literals from the __cstring section

    :param lief.MachO.FatBinary macho: Mach-O object

    :yield: cstring literals
    """
    data = obtain_section_data("__cstring", macho)
    if data:
        for entry in data.split(b"\0"):
            if entry:
                yield entry


def obtain_cstring_literals(macho: lief.MachO.FatBinary) -> List[bytes]:
    """
    Obtain cstring literals obtained from the __cstring section

    :param lief.MachO.FatBinary macho: Parsed Mach-O object

    :return: Obtained user strings
    :rtype: list
    """
    return [entry for entry in iter_cstring_literals(macho)]


def obtain_fat_memory_offset(offset: int, macho: lief.MachO.FatBinary) -> Optional[int]:
    """
    Obtain a FatBinary memory offset

    :param int offset: Physical offset
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: Memory offset
    :rtype: int
    """
    for idx in range(macho.size):
        macho_bin = macho.at(idx)
        # Difference from obtain_memory_offset
        if mem_off := macho_bin.offset_to_virtual_address(offset - macho_bin.fat_offset):
            if mem_off != 0xffffffffffffffff:
                return mem_off


def obtain_fat_physical_offset(mem_offset: int, macho: lief.MachO.FatBinary) -> Optional[int]:
    """
    Obtain a FatBinary physical offset

    :param int mem_offset: Memory offset
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: Physical offset
    :rtype: int
    """
    for idx in range(macho.size):
        macho_bin = macho.at(idx)
        if macho_bin.is_valid_addr(mem_offset):
            offset = macho_bin.virtual_address_to_offset(mem_offset)
            # 0xffffffffffffffff indicates an offset was not properly converted
            if offset != 0xffffffffffffffff:
                return offset + macho_bin.fat_offset


def obtain_memory_offset(offset: int, macho: lief.MachO.FatBinary) -> Optional[int]:
    """
    Obtain a memory offset

    :param int offset: Physical offset
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: Memory offset
    :rtype: int
    """
    for idx in range(macho.size):
        macho_bin = macho.at(idx)
        if mem_off := macho_bin.offset_to_virtual_address(offset):
            if mem_off != 0xffffffffffffffff:
                return mem_off


def obtain_physical_offset(mem_offset: int, macho: lief.MachO.FatBinary) -> Optional[int]:
    """
    Obtain a physical offset

    :param int mem_offset: Memory offset
    :param lief.MachO.FatBinary macho: Mach-O object

    :return: Physical offset
    :rtype: int
    """
    for idx in range(macho.size):
        macho_bin = macho.at(idx)
        if macho_bin.is_valid_addr(mem_offset):
            offset = macho_bin.virtual_address_to_offset(mem_offset)
            # 0xffffffffffffffff indicates an offset was not properly converted
            if offset != 0xffffffffffffffff:
                return offset


def MachOPointer(mem_off, subcon, macho=None):
    r"""
    Converts a MachO.Binary virtual address to an offset

    Example:
    spec = Struct(
        'offset' / Int64ul,
        'data' / MachOPointer(this.offset, Bytes(100))
    )

    spec.parse(file_data, macho=macho_object)

    :param mem_off: an int or a function that represents the memory offset for the equivalent physical offset.
    :param subcon: the subcon to use at the offset
    :param macho: Optional MachO file object. (if not supplied here, this must be supplied during parse()/build()
    """
    def _obtain_physical_offset(ctx):
        _macho = macho or ctx._params.macho
        _mem_off = mem_off(ctx) if callable(mem_off) else mem_off
        if _macho is None:
            raise construct.ConstructError('Input file is not Mach-O')
        # Iterate the binaries to find one which contains the memory address range
        for idx in range(_macho.size):
            mbin = _macho.at(idx)
            if mbin.is_valid_addr(_mem_off):
                offset = mbin.virtual_address_to_offset(_mem_off)
                # 0xffffffffffffffff indicates an offset was not properly converted
                if offset != 0xffffffffffffffff:
                    return offset
        raise construct.ConstructError('Unable to decode virtual address')

    return construct.Pointer(_obtain_physical_offset, subcon)


def MachOFatPointer(mem_off, subcon, macho=None):
    r"""
    Converts a MachO.Binary virtual address to an offset, offset by the start of the MachO binary

    spec.parse(file_data, macho=macho_object)

    :param mem_off: an int or a function that represents the memory offset for the equivalent physical offset.
    :param subcon: the subcon to use at the offset
    :param macho: Optional MachO file object. (if not supplied here, this must be supplied during parse()/build()
    """
    def _obtain_physical_offset(ctx):
        _macho = macho or ctx._params.macho
        _mem_off = mem_off(ctx) if callable(mem_off) else mem_off
        if _macho is None:
            raise construct.ConstructError('Input file is not Mach-O')
        # Iterate the binaries to find one which contains the memory address range
        for idx in range(_macho.size):
            mbin = _macho.at(idx)
            if mbin.is_valid_addr(_mem_off):
                offset = mbin.virtual_address_to_offset(_mem_off)
                # 0xffffffffffffffff indicates an offset was not properly converted
                if offset != 0xffffffffffffffff:
                    # Difference from MachOPointer
                    return offset + mbin.fat_offset
        raise construct.ConstructError('Unable to decode virtual address')

    return construct.Pointer(_obtain_physical_offset, subcon)


class MachOMemoryAddress(construct.Adapter):
    r"""
    Adapter used to convert an int representing an MachO memory address into a physical address.

    """
    def __init__(self, subcon, macho=None):
        """
        :param macho: Optional ELF file object. (if not supplied here, this must be supplied during parse()/build()
        :param subcon: subcon to parse memory offset.
        """
        super().__init__(subcon)
        self._macho = macho

    def _encode(self, obj, context, path):
        macho = self._macho or context._params.macho
        if macho is None:
            raise construct.ConstructError('Input file is not Mach-O')
        address = obtain_physical_offset(obj, macho=macho)
        if address is None:
            raise construct.ConstructError('Unable to decode virtual address.')
        return address

    def _decode(self, obj, context, path):
        macho = self._macho or context._params.macho
        if macho is None:
            raise construct.ConstructError('Input file is not Mach-O')
        address = obtain_memory_offset(obj, macho=macho)
        if address is None:
            raise construct.ConstructError('Unable to encode physical address.')
        return address


class MachOFatMemoryAddress(construct.Adapter):
    r"""
    Adapter used to convert an int representing an MachO memory address into a physical address, offset by the start of
    the MachO binary

    """
    def __init__(self, subcon, macho=None):
        """
        :param macho: Optional ELF file object. (if not supplied here, this must be supplied during parse()/build()
        :param subcon: subcon to parse memory offset.
        """
        super().__init__(subcon)
        self._macho = macho

    def _encode(self, obj, context, path):
        macho = self._macho or context._params.macho
        if macho is None:
            raise construct.ConstructError('Input file is not Mach-O')
        address = obtain_fat_physical_offset(obj, macho=macho)
        if address is None:
            raise construct.ConstructError('Unable to decode virtual address.')
        return address

    def _decode(self, obj, context, path):
        macho = self._macho or context._params.macho
        if macho is None:
            raise construct.ConstructError('Input file is not Mach-O')
        address = obtain_fat_memory_offset(obj, macho=macho)
        if address is None:
            raise construct.ConstructError('Unable to encode physical address.')
        return address