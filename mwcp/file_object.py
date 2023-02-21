"""
Implements FileObject class used to provide an interface for the file being parsed.
"""
from __future__ import annotations
import contextlib
import datetime
import hashlib
import io
import logging
import os
import pathlib
import shutil
import weakref

import sys
import tempfile
import warnings
from typing import List, Optional, Iterable, Union, TYPE_CHECKING, ContextManager

import pefile

from mwcp import metadata
from mwcp.utils import elffileutils, pefileutils
from mwcp.utils.stringutils import convert_to_unicode, sanitize_filename

try:
    import kordesii
except ImportError:
    # Kordesii support is optional.
    kordesii = None

try:
    import dragodis
except ImportError:
    dragodis = None


if TYPE_CHECKING:
    from mwcp import Report


logger = logging.getLogger(__name__)


class FileObject(object):
    """
    This class represents a file object which is to be parsed by the MWCP parser.
    It is pushed into the dispatcher queue for processing.
    """

    # Collection of file_object instances that have been created.
    # This is necessary so the Runner can cleanup temp files that have been created
    # for backwards compatibility.
    # TODO: Remove this when original implementation of .file_path is removed.
    _instances: List[FileObject] = []

    def __init__(
        self,
        file_data: bytes,
        reporter=None,  # DEPRECATED
        pe: pefile.PE = None,
        file_name=None,
        file_path=None,
        def_stub=None,
        description=None,
        output_file=True,
        use_supplied_fname=True,
        use_arch=False,
        ext=".bin",
        derivation: str = None,
    ):
        """
        Initializes the FileObject.

        :param bytes file_data: Data for the file.
        :param pefile.PE pe: PE object for the file.
        :param mwcp.Report reporter: MWCP Report.
        :param str file_name: File name to use if file is not a PE or use_supplied_fname was specified.
        :param str file_path: Actual file path as found in the file system.
            (This is primarily used for the initial input file)
        :param str description: Description of the file object.
        :param bool output_file: Boolean indicating if file should be outputted when the dispatcher process the file.
        :param bool use_supplied_fname: Boolean indicating if the file_name should be used even if the file is a PE.
        :param str def_stub: def_stub argument to pass to obtain_original_filename()
        :param bool use_arch: use_arch argument to pass to obtain_original_filename()
        :param str ext: default extension to use if not determined from pe file.
        :param derivation: Description of how the file was obtained or its categorization.
            e.g. "decrypted", "deobfuscated", "supplemental"
        """
        if reporter:
            warnings.warn(
                "Passing a reporter argument to FileObject is deprecated and will be removed in a future release. "
                "Please update your code to not include the argument.",
                DeprecationWarning
            )

        # Ensure we are getting a bytes string. Libraries like pefile depend on this.
        if not isinstance(file_data, bytes):
            raise TypeError("file_data must be a bytes string.")

        self._file_path = file_path
        self._exists = bool(file_path)  # Indicates if the user provided the path and the file exists on the host file system.
        self._temp_path = None
        self._temp_path_ctx = None
        self._md5 = None
        self._sha1 = None
        self._sha256 = None
        self._stack_strings = None
        self._static_strings = None
        self._resources = None
        self._elf = None
        self._elf_attempt = False
        self.output_file = output_file
        self._outputted_file = False
        self._kordesii_cache = {}
        self.parent = None  # Parent FileObject from which FileObject was extracted from (this is set externally).
        self.parser = None  # This will be set by the dispatcher.
        self.children = []  # List of residual FileObject
        self._data = file_data
        self._use_arch = use_arch
        self._ext = ext
        self._def_stub = def_stub
        self._report_ref = weakref.ref(reporter) if reporter else None  # DEPRECATED
        self.description = description
        self.derivation = derivation
        self.knowledge_base = {}
        self.tags = set()

        self.pe = pe or pefileutils.obtain_pe(file_data)

        use_supplied_fname = use_supplied_fname or not self.pe

        if file_path:
            file_name = pathlib.PurePath(file_path).name

        if file_name and use_supplied_fname:
            self._name = file_name
        else:
            self._name = pefileutils.obtain_original_filename(
                def_stub or self.md5, pe=self.pe, use_arch=use_arch, ext=ext
            )
        self._name = convert_to_unicode(self._name)

        # Keep track of instances so we can clean them up when Runner finishes.
        self._instances.append(self)

    def __enter__(self):
        warnings.warn(
            "Using FileObject directly as a context manager is deprecated. "
            "Please use .open() instead.",
            DeprecationWarning
        )
        self._open_file = io.BytesIO(self.data)
        return self._open_file

    def __exit__(self, *args):
        self._open_file.close()

    def __repr__(self):
        return f"<{self.name} ({self.md5}) : {self.description}>"

    @classmethod
    def from_path(cls, file_path: Union[str, os.PathLike], **kwargs) -> "FileObject":
        """
        Generate FileObject from existing file on system by path.
        """
        with open(file_path, "rb") as fo:
            return FileObject(fo.read(), file_path=str(file_path), **kwargs)

    @contextlib.contextmanager
    def open(self):
        """
        This allows us to use the file_data as a file-like object when used as a context manager.

        e.g.
            >> file_object = FileObject('hello world', None)
            >> with file_object.open() as fo:
            ..     _ = fo.seek(6)
            ..     print fo.read()
            world
        """
        with io.BytesIO(self.data) as fo:
            yield fo

    def _clear_temp_path_ctx(self):
        """
        Cleans up temporary file if created.
        TODO: This is temporary in order to support backwards compatibility.
        """
        if self._temp_path_ctx:
            self._temp_path_ctx.__exit__(*sys.exc_info())
            self._temp_path_ctx = None
            self._temp_path = None

    @classmethod
    def _cleanup(cls):
        """
        Cleans up instances of FileObject.
        """
        for file_object in cls._instances:
            file_object._clear_temp_path_ctx()
            file_object._report_ref = None
        cls._instances = []

    def add_tag(self, *tags: Iterable[str]) -> FileObject:
        """
        Adds tag(s) for the file.

        :param tags: One or more tags to add to the file.
        :returns: self to make this function chainable.
        """
        for tag in tags:
            self.tags.add(tag)
        return self

    @property
    def reporter(self):
        warnings.warn(
            "FileObject.reporter has been deprecated and should not be accessed from FileObject.",
            DeprecationWarning
        )
        return self._report_ref and self._report_ref()

    @property
    def siblings(self) -> List[FileObject]:
        """List of FileObjects that came from the same parent."""
        if not self.parent:
            return []
        return [fo for fo in self.parent.children if fo is not self]

    @property
    def ancestors(self) -> List[FileObject]:
        """List of FileObjects for the full parental hierarchy."""
        if not self.parent:
            return []
        return [self.parent, *self.parent.ancestors]

    @property
    def descendants(self) -> List[FileObject]:
        """List of FileObjects that came from the current file."""
        ret = list(self.children)
        for child in self.children:
            ret.extend(child.descendants)
        return ret

    @property
    def file_data(self):
        warnings.warn(
            ".file_data is deprecated. Please use .data instead.",
            DeprecationWarning
        )
        return self.data

    @file_data.setter
    def file_data(self, value):
        warnings.warn(
            ".file_data is deprecated. Please use .data instead.",
            DeprecationWarning
        )
        raise ValueError("FileObject.file_data is ready only!")

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def elf(self):
        """Returns elftools.ELFFile object or None if not an ELF file."""
        if not self._elf and not self._elf_attempt:
            self._elf_attempt = True
            self._elf = elffileutils.obtain_elf(self.data)
        return self._elf

    # TODO: Deprecate "file_name" name in exhange for "name"?
    @property
    def file_name(self):
        warnings.warn(
            ".file_name attribute is deprecated. Please use .name instead.",
            DeprecationWarning
        )
        return self.name

    @file_name.setter
    def file_name(self, value):
        warnings.warn(
            ".file_name attribute is deprecated. Please use .name instead.",
            DeprecationWarning
        )
        self.name = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        # If someone changes the name, record the rename.
        value = convert_to_unicode(value)
        if self._name != value:
            logger.info("Renamed {} to {}".format(self._name, value))
        self._name = value

    @property
    def ext(self):
        """The extension of the file."""
        return pathlib.PurePath(self.name).suffix

    @ext.setter
    def ext(self, new_ext: str):
        """Sets a new extension for the file."""
        if not new_ext.startswith("."):
            new_ext = f".{new_ext}"
        self.name = pathlib.PurePath(self.name).stem + new_ext

    @property
    def parser_history(self):
        """
        Returns a history of the parser classes (including current) that has lead to the creation of the file object.
        e.g. [MalwareDropper, MalwareLoader, MalwareImplant]
        :return list: List of parser classes.
        """
        history = [self.parser]
        parent = self.parent
        while parent:
            history.append(parent.parser)
            parent = parent.parent
        return reversed(history)

    @property
    def md5(self):
        """
        Returns md5 hash of file.
        :return: hash of the file as a hex string
        """
        if not self._md5:
            self._md5 = hashlib.md5(self.data).hexdigest()
        return self._md5

    @property
    def sha1(self):
        """
        Returns sha1 hash of file.
        :return: hash of the file as a hex string
        """
        if not self._sha1:
            self._sha1 = hashlib.sha1(self.data).hexdigest()
        return self._sha1

    @property
    def sha256(self):
        """
        Returns sha256 hash of file.
        :return: hash of the file as a hex string
        """
        if not self._sha256:
            self._sha256 = hashlib.sha256(self.data).hexdigest()
        return self._sha256

    @property
    def compile_time(self) -> Optional[datetime.datetime]:
        """
        Returns UTC datetime of compile time (if applicable)
        """
        if self.pe:
            timestamp = self.pe.FILE_HEADER.TimeDateStamp
            return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)

    @contextlib.contextmanager
    def temp_path(self):
        """
        Context manager for creating a temporary full file path to the file object.
        This is useful for when you want to use this file on libraries which require
        a file path instead of data or file-like object. (e.g. cabinet).

        WARNING: Take care when using this function. This will cause the potentially
            malicious file to be written out to the file system!

        Usage:
            with file_object.temp_path() as file_path:
                _some_library_that_needs_a_path(file_path)
        """
        # TODO: Provide and option to change location of temporary files through the use
        #   of the configuration file.
        with tempfile.TemporaryDirectory(prefix="mwcp_") as tmpdir:
            temp_file = os.path.join(tmpdir, sanitize_filename(self.name) if self.name else self.md5)
            with open(temp_file, "wb") as fo:
                fo.write(self.data)
            yield temp_file

    @property
    def file_path(self) -> Optional[str]:
        """
        The full file path of the file object if backed by a real file on the file system.
        (This is usually just for the original input file.)

        This property is currently set to be backwards compatible with the original usage
        which has been moved to .temp_path()
        In the future, this attribute will only be applicable if the FileObject is backed
        by a real file on the file system and will be None otherwise.
        In the meantime, you can confirm if this attribute represents a real file path
        (future usage) or a temporary path (deprecated usage) by checking if ._exists is
        True or False first. Eventually, this check will no longer be needed.
        """
        warnings.warn(
            "Original usage of .file_path is deprecated. Please use .temp_path() instead. "
            "In the future, this attribute will only be applicable if the FileObject "
            "is backed by a real file on the file system.",
            DeprecationWarning
        )
        if self._file_path:
            return self._file_path

        if not self._temp_path:
            self._clear_temp_path_ctx()
            self._temp_path_ctx = self.temp_path()
            self._temp_path = self._temp_path_ctx.__enter__()
        return self._temp_path

    @file_path.setter
    def file_path(self, value):
        """
        Setter for the file_path attribute. This is used if an external entity can
        provided a valid file_path.
        """
        self._file_path = value
        self._exists = bool(value)

    @property
    def stack_strings(self) -> List[str]:
        """
        Returns the stack strings for the file.
        """
        if not self._stack_strings:
            kordesii_reporter = self.run_kordesii_decoder("stack_string")
            self._stack_strings = kordesii_reporter.get_strings()
        return self._stack_strings

    # TODO: Create a static_strings property?

    @property
    def resources(self) -> List[pefileutils.Resource]:
        """Returns a list of the PE resources for the given file."""
        if self.pe and not self._resources:
            self._resources = list(pefileutils.iter_rsrc(self.pe))
        return self._resources

    @property
    def is_64bit(self) -> Optional[bool]:
        """
        Evaluates whether the file is a 64 bit pe file.

        :return: True if 64-bit, False if 32-bit, None if could not be determined.
        """
        if not self.pe:
            return None
        return pefileutils.is_64bit(pe=self.pe)

    @property
    def architecture(self) -> Optional[str]:
        """
        The architecture of the file (if an executable).
        """
        if self.pe:
            return pefileutils.obtain_architecture_string(pe=self.pe, bitterm=False)
        elif self.elf:
            arch = self.elf.get_machine_arch()
            if arch == "<unknown>":
                arch = None
            return arch
        else:
            return None

    def output(self):
        """
        Outputs FileObject instance to reporter if it hasn't already been outputted.
        """
        warnings.warn(
            "output() is deprecated. Please call report.add() on a File metadata "
            "object to report and output on a file instead.",
            DeprecationWarning
        )
        if self.output_file:
            self.reporter.add(metadata.File.from_file_object(self))

    @contextlib.contextmanager
    def disassembly(self, disassembler: str = None, report: Report = None, **config) -> ContextManager["dragodis.Disassembler"]:
        """
        Produces a Dragodis Disassembler object for the file.
        Dragodis must be installed for this work.

        e.g.
            with self.file_object.disassembly() as dis:
                mnemonic = dis.get_instruction(0x1234).mnemonic

        :param disassembler: Name of the backend disassembler to use.
            (e.g. "ida" or "ghidra")
            If not provided, the disassembler setup in the environment variable
            DRAGODIS_DISASSEMBLER will be used.
            (It is usually recommended to not set the variable so the parser is cross
            compatible with any disassembler Dragodis supports.)
        :param report: Provide the Report object if you want the annotated disassembler project file to
            be added after processing.
            This is usually only recommended if the parser plans to annotate the disassembly. e.g. API resolution
        """
        if not dragodis:
            raise RuntimeError("Please install Dragodis to use this function.")

        with self.temp_path() as file_path:
            with dragodis.open_program(file_path, disassembler, **config) as dis:
                bit_size = dis.bit_size
                yield dis

            # After processing we want to save the annotated project file if report was provided.
            if report:
                project_file = None
                if dis.name.casefold() == "ida":
                    ext = ".i64" if bit_size == 64 else ".idb"
                    project_file = dis.input_path.parent / (dis.input_path.name + ext)
                elif dis.name.casefold() == "ghidra":
                    folder_path = dis.input_path.parent / (dis.input_path.name + "_ghidra")
                    project_file = pathlib.Path(shutil.make_archive(
                        str(folder_path), format="zip", root_dir=folder_path
                    ))
                if project_file and project_file.exists():
                    data = project_file.read_bytes()
                    report.add(metadata.File(
                        name=project_file.name,
                        data=data,
                        description=f"{dis.name} Project File",
                        derivation="supplemental",
                    ))

    def run_kordesii_decoder(self, decoder_name: str, warn_no_strings=True, **run_config):
        """
        Run the specified kordesii decoder against the file data.  The reporter object is returned
        and can be accessed as necessary to obtain output files, etc.

        :param decoder_name: name of the decoder to run
        :param warn_no_strings: Whether to produce a warning if no string were found.
        :param run_config: Run configuration options to pass along to kordesii.run_ida()

        :return: Instance of the kordesii_reporter.

        :raises RuntimeError: If kordesii is not installed.
        """
        if not kordesii:
            raise RuntimeError("Please install kordesii to use this function.")

        # Pull from cache if we already ran this decoder.
        if decoder_name in self._kordesii_cache:
            return self._kordesii_cache[decoder_name]

        logger.info(f"Running {decoder_name} kordesii decoder on file {self.name}.")
        # Ensure decoderdir sources are populated
        kordesii.register_entry_points()

        kordesii_reporter = kordesii.Reporter(base64outputfiles=True)

        if "log" not in run_config:
            run_config["log"] = True
        kordesii_reporter.run_decoder(decoder_name, data=self.data, **run_config)

        if warn_no_strings:
            decrypted_strings = kordesii_reporter.get_strings()
            if not decrypted_strings:
                # Not necessarily a bad thing, the decoder might be used for something else.
                logger.info(f"No decrypted strings were returned by the decoder for file {self.name}.")

        # Cache results
        self._kordesii_cache[decoder_name] = kordesii_reporter

        return kordesii_reporter
