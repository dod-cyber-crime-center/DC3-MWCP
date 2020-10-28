"""
pecon - PE file reCONstructor

Usage:
    >>> from mwcp.utils import pecon

    # Create a PE object
    >>> pe = pecon.PE()

    # Fill in pe with known information (fields not provided will contain a default as defined in the PE constructor)
    >>> pe.DosHeader.e_lfanew = 0x3211
    >>> pe.OptionalHeader.SizeOfCode = 0x3141241
    >>> pe.OptionalHeader.AddressOfEntryPoint = 0x43222
    >>> pe.OptionalHeader.Subsystem = pecon.IMAGE_SUBSYSTEM_WINDOWS_GUI
    # DataDirectory is a list of IMAGE_DATA_DIRECTORY structs.
    # By default it contains the standard 16, which can be accessed with indexes or though helper attributes
    # ("imports", "exports", etc)
    # NOTE: While it would make more sense to call it "DataDirectories", we are trying to be
    #       consistent with Microsoft's names.
    >>> pe.OptionalHeader.DataDirectory.imports.VirtualAddress = 0x101
    >>> pe.OptionalHeader.DataDirectory.imports.Size = 20
    # Create pecon.Section() objects to fill in section information.
    # (By default there are no sections.)
    >>> pe.SectionTable.append(pecon.Section(Name='.text', VirtualSize=4, VirtualAddress=0x3422, data=b'blah'))

    # Generate file data.
    >>> pe_data = pe.build()
    # To only build the header, you can tell it to avoid writing the section data.
    >>> pe_data = pe.build(write_section_data=False)

    # You can also modifiy fields in an already existing exe file.
    >>> pe = pecon.PE(exe_data)
    >>> pe.OptionalHeader.SizeOfCode = 0x3422
    >>> pe_data = pe.build()


"""

import copy
import io
import logging

logger = logging.getLogger(__name__)

from mwcp.utils import construct
from construct import this

# Expose the constants users will need.
from mwcp.utils.construct.windows_constants import *


# Overwrite Container class to provide deepcopy functionality.
class Container(construct.Container):

    @classmethod
    def from_container(cls, container_object):
        """Factory method for converting an already existing Container object."""
        _dict = {}
        for key, value in container_object.items():
            if isinstance(value, dict):
                value = cls.from_container(value)
            if isinstance(value, list):
                for i in range(len(value)):
                    # one level is all that is necessary for what we are doing.
                    if isinstance(value[i], dict):
                        value[i] = cls.from_container(value[i])
            _dict[key] = value
        return cls(_dict)

    def __deepcopy__(self, memo):
        _copy = Container()
        for key, value in self.items():
            _copy[key] = copy.deepcopy(value, memo)
        return _copy


class DataDirectories(construct.ListContainer):
    """
    A list of IMAGE_DATA_DIRECTORY entries

    Provides convenience properties for accessing standard directories by name.

    :param int size: Number of directory entries. defaults to the standard size of 16
    """

    def __init__(self, size=16):
        super(DataDirectories, self).__init__()
        for _ in range(size):
            self.append(Container(VirtualAddress=0, Size=0))

    def sizeof(self):
        return construct.IMAGE_DATA_DIRECTORY.sizeof() * len(self)

    # Provide convenience properties for accessing standard data directories.

    @property
    def exports(self):
        return self[construct.DATA_DIR_INDEX_EXPORTS]

    @exports.setter
    def exports(self, value):
        self[construct.DATA_DIR_INDEX_EXPORTS] = value

    @property
    def imports(self):
        return self[construct.DATA_DIR_INDEX_IMPORTS]

    @imports.setter
    def imports(self, value):
        self[construct.DATA_DIR_INDEX_IMPORTS] = value

    @property
    def resource(self):
        return self[construct.DATA_DIR_INDEX_RESOURCE]

    @resource.setter
    def resource(self, value):
        self[construct.DATA_DIR_INDEX_RESOURCE] = value

    @property
    def exception(self):
        return self[construct.DATA_DIR_INDEX_EXCEPTION]

    @exception.setter
    def exception(self, value):
        self[construct.DATA_DIR_INDEX_EXCEPTION] = value

    @property
    def certificate(self):
        return self[construct.DATA_DIR_INDEX_CERTIFICATE]

    @certificate.setter
    def certificate(self, value):
        self[construct.DATA_DIR_INDEX_CERTIFICATE] = value

    @property
    def base_reloc(self):
        return self[construct.DATA_DIR_INDEX_BASE_RELOC]

    @base_reloc.setter
    def base_reloc(self, value):
        self[construct.DATA_DIR_INDEX_BASE_RELOC] = value

    @property
    def debug(self):
        return self[construct.DATA_DIR_INDEX_DEBUG]

    @debug.setter
    def debug(self, value):
        self[construct.DATA_DIR_INDEX_DEBUG] = value

    @property
    def architecture(self):
        return self[construct.DATA_DIR_INDEX_ARCHITECTURE]

    @architecture.setter
    def architecture(self, value):
        self[construct.DATA_DIR_INDEX_ARCHITECTURE] = value

    @property
    def global_ptr(self):
        return self[construct.DATA_DIR_INDEX_GLOBAL_PTR]

    @global_ptr.setter
    def global_ptr(self, value):
        self[construct.DATA_DIR_INDEX_GLOBAL_PTR] = value

    @property
    def tls(self):
        return self[construct.DATA_DIR_INDEX_TLS]

    @tls.setter
    def tls(self, value):
        self[construct.DATA_DIR_INDEX_TLS] = value

    @property
    def load_config(self):
        return self[construct.DATA_DIR_INDEX_LOAD_CONFIG]

    @load_config.setter
    def load_config(self, value):
        self[construct.DATA_DIR_INDEX_LOAD_CONFIG] = value

    @property
    def bound_import(self):
        return self[construct.DATA_DIR_INDEX_BOUND_IMPORT]

    @bound_import.setter
    def bound_import(self, value):
        self[construct.DATA_DIR_INDEX_BOUND_IMPORT] = value

    @property
    def import_address(self):
        return self[construct.DATA_DIR_INDEX_IMPORT_ADDRESS]

    @import_address.setter
    def import_address(self, value):
        self[construct.DATA_DIR_INDEX_IMPORT_ADDRESS] = value

    @property
    def dely_import_descriptor(self):
        return self[construct.DATA_DIR_INDEX_DELAY_IMPORT_DESCRIPTOR]

    @dely_import_descriptor.setter
    def dely_import_descriptor(self, value):
        self[construct.DATA_DIR_INDEX_DELAY_IMPORT_DESCRIPTOR] = value

    @property
    def clr_header(self):
        return self[construct.DATA_DIR_INDEX_CLR_HEADER]

    @clr_header.setter
    def clr_header(self, value):
        self[construct.DATA_DIR_INDEX_CLR_HEADER] = value


class Section(Container):
    """
    Container for IMAGE_SECTION_HEADER

    (Provides defaults for non-filled values.)
    """

    def __init__(self, *args, **kw):
        _section_header = {
            'Name': '',
            'VirtualSize': 0,
            'VirtualAddress': 0,
            'SizeOfRawData': 0,
            'PointerToRawData': 0,
            'PointerToRelocations': 0,
            'PointerToLinenumbers': 0,
            'NumberOfrelocations': 0,
            'NumberOfLinenumbers': 0,
            'Characteristics': [],
            'data': '',
        }
        super(Section, self).__init__(_section_header)
        for arg in args:
            self.update(arg)
        self.update(kw)


class PE(Container):

    def __init__(self, data=None, is_64bit=False):
        """

        :param data: Data from an existing PE file, if provided, this will be used as the base line.
        :param is_64bit: Whether to make a 64 bit or 32 bit PE file. Defaults to 32 bit.
            (NOTE: This is only applicable if not passing in data.)
        """

        super(PE, self).__init__()

        if data:
            # If user provided data, parse it and use it as a base point.
            self._parse(data)
            return

        # Otherwise create a default pe.

        _characteristics = [
            construct.IMAGE_FILE_RELOCS_STRIPPED,
            construct.IMAGE_FILE_EXECUTABLE_IMAGE,
            construct.IMAGE_FILE_LINE_NUMS_STRIPPED,
            construct.IMAGE_FILE_LOCAL_SYMS_STRIPPED,
        ]

        if is_64bit:
            _magic = construct.IMAGE_NT_OPTIONAL_HDR64_MAGIC
            _machine = construct.IMAGE_FILE_MACHINE_AMD64
        else:
            _magic = construct.IMAGE_NT_OPTIONAL_HDR32_MAGIC
            _machine = construct.IMAGE_FILE_MACHINE_I386
            _characteristics.append(construct.IMAGE_FILE_32BIT_MACHINE)

        _dos_header = Container({
            'e_magic': b'MZ',
            'e_cblp': 0x90,
            'e_cp': 0x03,
            'e_crlc': 0,
            'e_cparhdr': 4,
            'e_mimalloc': 0,
            'e_maxalloc': 0xffff,
            'e_ss': 0,
            'e_sp': 184,
            'e_csum': 0,
            'e_ip': 0,
            'e_cs': 0,
            'e_lfarlc': 64,
            'e_ovno': 0,
            'e_res1': b'\x00\x00\x00\x00\x00\x00\x00\x00',
            'e_oemid': 0,
            'e_oeminfo': 0,
            'e_res2': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            'e_lfanew': 224,
        })

        _data_directories = DataDirectories()

        _optional_header = Container({
            'Magic': _magic,
            'MajorLinkerVersion': 1,
            'MinorLinkerVersion': 71,
            'SizeOfCode': 0,
            'SizeOfInitializedData': 0,
            'SizeOfUninitializedData': 0,
            'AddressOfEntryPoint': 0,
            'BaseOfCode': 0,
            'BaseOfData': 0,
            'ImageBase': 0,
            'SectionAlignment': 4096,
            'FileAlignment': 512,
            'MajorOperatingSystemVersion': 1,
            'MinorOperatingSystemVersion': 0,
            'MajorImageVersion': 0,
            'MinorImageVersion': 0,
            'MajorSubsystemVersion': 5,
            'MinorSubsystemVersion': 1,
            'Win32VersionValue': 0,  # must be 0 (but I guess still allow them to change it)
            'SizeOfImage': 0,
            'SizeOfHeaders': 0,
            'CheckSum': 0,
            'Subsystem': construct.IMAGE_SUBSYSTEM_WINDOWS_CUI,
            'DllCharacteristics': [],
            'SizeOfStackReserve': 1048576,
            'SizeOfStackCommit': 4096,
            'SizeOfHeapReserve': 1048576,
            'SizeOfHeapCommit': 4096,
            'LoaderFlags': 0,
            'NumberOfRvaAndSizes': _data_directories.sizeof(),
            'DataDirectory': _data_directories,
        })

        _file_header = Container({
            'Machine': _machine,
            'NumberOfSections': 0,
            'TimeDateStamp': 0,
            'PointerToSymbolTable': 0,
            'NumberOfSymbols': 0,
            'SizeOfOptionalHeader': construct.IMAGE_OPTIONAL_HEADER.sizeof(**_optional_header),
            'Characteristics': _characteristics,
        })

        self.DosHeader = Container(_dos_header)

        # Default to "ret" opcode.
        self.DosStub = b'\xc3'

        self.NTHeaders = Container(
            Signature=0x4550,   # b'PE\x00\x00'
            FileHeader=Container(_file_header),
            OptionalHeader=Container(_optional_header)
        )

        self.SectionTable = construct.ListContainer()

    def _parse(self, data):
        """
        Parses data containing PE file and updates dictionary to reflect results.

        :raises ConstructError: If provided data could not be parsed (ie. not a pe)
        """
        pe = construct.PEFILE_HEADER.parse(data)

        # Convert Container classes to use ours, so we can deepcopy.
        pe = Container.from_container(pe)

        # Convert the FlagEnums into list of constants.
        for section in pe.SectionTable:
            if isinstance(section.Characteristics, dict):
                section.Characteristics = [flag for flag, value in section.Characteristics.items() if value]
            section.data = data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        file_header = pe.NTHeaders.FileHeader
        if isinstance(file_header.Characteristics, dict):
            file_header.Characteristics = [
                flag for flag, value in file_header.Characteristics.items() if value]
        optional_header = pe.NTHeaders.OptionalHeader
        if isinstance(optional_header.DllCharacteristics, dict):
            optional_header.DllCharacteristics = [
                flag for flag, value in optional_header.DllCharacteristics.items() if value]

        self.update(pe)

    def _fix_section(self, section):
        """Fixes up section container for building."""
        section_copy = copy.deepcopy(section)

        # Formulate characteristics based on name if they weren't provided.
        if not section_copy.Characteristics:
            _characteristics = [construct.IMAGE_SCN_MEM_READ]
            if section_copy.Name == u'.text':
                _characteristics += [construct.IMAGE_SCN_CNT_CODE, construct.IMAGE_SCN_MEM_EXECUTE]
            else:
                _characteristics += [construct.IMAGE_SCN_CNT_INITIALIZED_DATA]
            if section_copy.Name == u'.data':
                _characteristics += [construct.IMAGE_SCN_MEM_WRITE]
            if section_copy.Name == u'.reloc':
                _characteristics += [construct.IMAGE_SCN_MEM_DISCARDABLE]
            section_copy.Characteristics = _characteristics

        # FlagEnums must be a dictionary.
        if isinstance(section_copy.Characteristics, list):
            section_copy.Characteristics = {flag: True for flag in section_copy.Characteristics}

        # Fix up data to be consistent.
        data_size = max(section_copy.SizeOfRawData, len(section_copy.data))
        section_copy.SizeOfRawData = data_size
        section_copy.data = section_copy.data.ljust(data_size, b'\x00')[:data_size]

        return section_copy

    def build(self, write_section_data=True):
        """
        Generate PE file.

        :param write_section_data: Whether to include section data (otherwise only the headers are written)

        :returns bytes: PE file data.

        :raises ValueError: If set attributes contains contradicting data.
        """
        pe = copy.deepcopy(self)

        # Pad dos stub to match e_lfanew. (Warn if dos stub is too large.)
        dos_stub_size = pe.DosHeader.e_lfanew - construct.IMAGE_DOS_HEADER.sizeof()
        if len(pe.DosStub) > dos_stub_size:
            raise ValueError(
                'Provided DOS stub is too large for provided DosHeader.e_lfanew: {}'.format(pe.DosHeader.e_lfanew))
        pe.DosStub = pe.DosStub.ljust(dos_stub_size, b'\x00')

        # Fix file header.
        file_header = pe.NTHeaders.FileHeader
        if file_header.NumberOfSections and file_header.NumberOfSections != len(pe.SectionTable):
            logger.debug(
                'NTHeaders.FileHeader.NumberOfSections does not equal the number of sections provided. Auto-adjusting.')
        file_header.NumberOfSections = len(pe.SectionTable)
        if isinstance(file_header.Characteristics, list):
            file_header.Characteristics = {flag: True for flag in file_header.Characteristics}

        # Fix sections.
        pe.SectionTable = list(map(self._fix_section, pe.SectionTable))

        # Fix optional header.
        optional_header = pe.NTHeaders.OptionalHeader
        number_of_rva_and_sizes = len(optional_header.DataDirectory)
        optional_header.NumberOfRvaAndSizes = number_of_rva_and_sizes
        file_header.SizeOfOptionalHeader = construct.IMAGE_OPTIONAL_HEADER.sizeof(**optional_header)
        if isinstance(optional_header.DllCharacteristics, list):
            optional_header.DllCharacteristics = {flag: True for flag in optional_header.DllCharacteristics}

        # SizeOfHeaders is the sum of the headers rounded by FileAlignment.
        headers_size = construct.PEFILE_HEADER.sizeof(**pe)
        file_alignment = optional_header.FileAlignment - 1
        headers_size = (headers_size + file_alignment) & 0xffffffff - file_alignment
        optional_header.SizeOfHeaders = headers_size

        pe_data = construct.PEFILE_HEADER.build(pe)

        # Add section data.
        if write_section_data:
            stream = io.BytesIO(pe_data)
            spec = construct.Pointer(this.PointerToRawData, construct.Bytes(this.SizeOfRawData))
            for section in pe.SectionTable:
                spec.build_stream(section.data, stream, **section)
            pe_data = stream.getvalue()

        return pe_data

    # Provide convenience properties for accessing NTHeader components.

    @property
    def OptionalHeader(self):
        return self.NTHeaders.OptionalHeader

    @OptionalHeader.setter
    def OptionalHeader(self, value):
        self.NTHeaders.OptionalHeader = value

    @property
    def FileHeader(self):
        return self.NTHeaders.FileHeader

    @FileHeader.setter
    def FileHeader(self, value):
        self.NTHeaders.FileHeader = value

    @property
    def Signature(self):
        return self.NTHeaders.Signature

    @Signature.setter
    def Signature(self, value):
        self.NTHeaders.Signature = value
