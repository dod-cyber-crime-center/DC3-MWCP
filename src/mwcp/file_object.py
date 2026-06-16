"""
Implements FileObject class used to provide an interface for the file being parsed.
"""
from __future__ import annotations
import contextlib
import functools
from datetime import datetime, timezone
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
from typing import List, Optional, Iterable, Union, TYPE_CHECKING, ContextManager, Unpack

import pefile
from elftools.elf.elffile import ELFFile

from mwcp import metadata, config
from mwcp.utils import elffileutils, pefileutils, machoutils
from mwcp.utils.stringutils import convert_to_unicode, sanitize_filename
from mwcp.exceptions import DependencyNotInstalled
from mwcp.config import settings

try:
    import kordesii
except ImportError:
    # Kordesii support is optional.
    kordesii = None

try:
    import dragodis
    import rugosa
except ImportError:
    dragodis = None
    rugosa = None

try:
    import patoolib
    from patoolib.util import PatoolError
except ImportError:
    patoolib = None
    PatoolError = None


if TYPE_CHECKING:
    from mwcp import Report, Parser
    from rugosa.emulation.emulator import IterContextArgs
    from rugosa.strings import DecodedString
    from dragodis.interface.string import String


logger = logging.getLogger(__name__)


class FileObject:
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
        data: Union[bytes, bytearray] = None,
        reporter=None,  # DEPRECATED
        pe: pefile.PE = None,
        name: str = None,
        elf: ELFFile = None,   # Must come after name for compatibility.
        path: str = None,
        description=None,
        ext=".bin",
        derivation: str = None,
        architecture: str = None,
        compile_time: datetime = None,
        parent: "FileObject" = None,
        parser: "Parser" = None,
        # TODO: Deprecate filename construction parameters.
        def_stub=None,
        use_supplied_fname=True,
        use_arch=False,
        **deprecated,
    ):
        """
        Initializes the FileObject.

        :param bytes/bytearray data: Data for the file.
        :param pefile.PE pe: PE object for the file.
        :param ELFFile elf: ELF object for the file.
        :param mwcp.Report reporter: MWCP Report.
        :param str name: File name to use if file is not a PE or use_supplied_fname was specified.
        :param str path: Actual file path as found in the file system.
            (This is primarily used for the initial input file)
        :param str description: Description of the file object.
        :param bool use_supplied_fname: Boolean indicating if the name should be used even if the file is a PE.
        :param str def_stub: def_stub argument to pass to obtain_original_filename()
        :param bool use_arch: use_arch argument to pass to obtain_original_filename()
        :param str ext: default extension to use if not determined from pe file.
        :param derivation: Description of how the file was obtained or its categorization.
            e.g. "decrypted", "deobfuscated", "supplemental"
        :param str architecture: Architecture of executable. (defaults to auto-detection)
        :param datetime compile_time: Time of compilation. (defaults to auto-detection)
        :param FileObject parent: Parent FileObject from which FileObject was extracted.
        :param Parser parser: Parser that created this FileObject.
        """
        if deprecated:
            warnings.warn(
                f"The following keyword arguments are deprecated: {', '.join(deprecated.keys())}",
                DeprecationWarning,
            )

        if reporter:
            warnings.warn(
                "Passing a reporter argument to FileObject is deprecated and will be removed in a future release. "
                "Please update your code to not include the argument.",
                DeprecationWarning
            )

        if data is None:
            data = deprecated.get("file_data")
        if data is not None:
            data = bytes(data)

        self._file_path = path or deprecated.get("file_path")
        self._exists = bool(self._file_path)  # Indicates if the user provided the path and the file exists on the host file system.
        self._temp_path = None
        self._temp_path_ctx = None
        self._md5 = None
        self._sha1 = None
        self._sha256 = None
        self._resources = None
        self._elf = elf
        self._elf_attempt = False
        self._macho = None
        self._macho_attempt = False
        self._pe = pe
        self._pe_attempt = False
        self._architecture = architecture
        self._compile_time = compile_time
        self._parent = None

        self.output_file = deprecated.get("output_file", True)
        self._outputted_file = False
        self._kordesii_cache = {}
        self.parent = parent
        self.parser = parser
        self.children = []  # List of residual FileObject
        self._data = data
        self._ext = ext
        self._report_ref = weakref.ref(reporter) if reporter else None  # DEPRECATED
        self.description = description
        self.derivation = derivation
        self.knowledge_base = {}
        self.tags = set()

        name = name or deprecated.get("file_name")
        if name and use_supplied_fname:
            name = convert_to_unicode(name)
        else:
            name = self._determine_filename(def_stub, use_arch, default=name)
        self._name = convert_to_unicode(name)

        # Keep track of instances so we can clean them up when Runner finishes.
        self._instances.append(self)

    def __enter__(self):
        warnings.warn(
            "Using FileObject directly as a context manager is deprecated. "
            "Please use .open() instead.",
            DeprecationWarning
        )
        if self.data is None:
            raise ValueError(f"FileObject has no data: {self.name}")
        self._open_file = io.BytesIO(self.data)
        return self._open_file

    def __exit__(self, *args):
        self._open_file.close()

    def __repr__(self):
        return f"<{self.name} ({self.md5}) : {self.description}>"

    def _determine_filename(self, def_stub: str = None, use_arch=False, default=None) -> str:
        """
        Determines an appropriate filename using given file path or executable metadata.
        """
        if self._file_path:
            return pathlib.PurePath(self._file_path).name
        elif self.pe:
            return pefileutils.obtain_original_filename(
                def_stub or self.md5,
                pe=self.pe, use_arch=use_arch, ext=self._ext
            )
        elif default:
            return default
        else:
            # TODO: We should leave name as None if we would otherwise just use the md5.
            return (def_stub or self.md5) + self._ext

    @property
    def parent(self) -> Optional["FileObject"]:
        return self._parent

    @parent.setter
    def parent(self, parent: Optional["FileObject"]):
        if self._parent == parent:
            return
        if self._parent and self in self._parent.children:
            self._parent.children.remove(self)
        self._parent = parent
        if parent and self not in parent.children:
            parent.children.append(self)

    @classmethod
    def from_path(cls, file_path: Union[str, os.PathLike], **kwargs) -> "FileObject":
        """
        Generate FileObject from existing file on system by path.
        """
        with open(file_path, "rb") as fo:
            return FileObject(fo.read(), file_path=str(file_path), **kwargs)

    @classmethod
    def from_metadata(cls, file: metadata.File, parent: "FileObject" = None) -> "FileObject":
        """
        Construct FileObject from a metadata element.
        NOTE: Data could be missing.
        """
        data = file.data
        file_path = file.file_path and pathlib.Path(file.file_path)
        if data is None and file_path and file_path.exists():
            data = file_path.read_bytes()

        file_object = cls(
            data,
            file_name=file.name,
            file_path=file.file_path,
            description=file.description,
            ext=file_path and file_path.suffix,
            derivation=file.derivation,
            architecture=file.architecture,
            compile_time=datetime.fromisoformat(file.compile_time) if file.compile_time else None,
            parent=parent,
        )
        if file.md5:
            file_object._md5 = file.md5
        if file.sha1:
            file_object._sha1 = file.sha1
        if file.sha256:
            file_object._sha256 = file.sha256
        file_object.add_tag(*file.tags)
        return file_object

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
        if self.data is None:
            raise ValueError(f"FileObject has no data: {self!r}")
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
    def data(self) -> Optional[bytes]:
        return self._data

    @property
    def pe(self) -> Optional[pefile.PE]:
        """Returns pefile.PE object or None if not a PE file."""
        if not self.data:
            return
        if not self._pe and not self._pe_attempt:
            self._pe_attempt = True
            self._pe = pefileutils.obtain_pe(self.data)
        return self._pe

    @property
    def elf(self) -> Optional[ELFFile]:
        """Returns elftools.ELFFile object or None if not an ELF file."""
        if not self.data:
            return
        if not self._elf and not self._elf_attempt:
            self._elf_attempt = True
            self._elf = elffileutils.obtain_elf(self.data)
        return self._elf

    @property
    def macho(self):
        """Returns lief.MachO.FatBinary object or None if not a Mach-O file."""
        if not self._macho and not self._macho_attempt:
            self._macho_attempt = True
            self._macho = machoutils.obtain_macho(self.data)
        return self._macho

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
            logger.info(f"Renamed {self._name} to {value}")
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
    def md5(self) -> str:
        """
        Returns md5 hash of file.
        :return: hash of the file as a hex string
        """
        if not self._md5:
            if self.data is None:
                raise ValueError(f"FileObject has no data: {self.name}")
            self._md5 = hashlib.md5(self.data).hexdigest()
        return self._md5

    @property
    def sha1(self) -> str:
        """
        Returns sha1 hash of file.
        :return: hash of the file as a hex string
        """
        if not self._sha1:
            if self.data is None:
                raise ValueError(f"FileObject has no data: {self.name}")
            self._sha1 = hashlib.sha1(self.data).hexdigest()
        return self._sha1

    @property
    def sha256(self) -> str:
        """
        Returns sha256 hash of file.
        :return: hash of the file as a hex string
        """
        if not self._sha256:
            if self.data is None:
                raise ValueError(f"FileObject has no data: {self!r}")
            self._sha256 = hashlib.sha256(self.data).hexdigest()
        return self._sha256

    @property
    def compile_time(self) -> Optional[datetime]:
        """
        Returns UTC datetime of compile time (if applicable)
        """
        if not self._compile_time:
            if self.pe:
                timestamp = self.pe.FILE_HEADER.TimeDateStamp
                self._compile_time = datetime.fromtimestamp(timestamp, timezone.utc)
        return self._compile_time

    @contextlib.contextmanager
    def temp_path(self, keep=False, extension: str = None):
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
        if self.data is None:
            raise ValueError(f"FileObject has no data: {self!r}")

        if keep or settings.keep_tmp:
            tmpdir = tempfile.mkdtemp(prefix="mwcp_")
            context = contextlib.nullcontext(tmpdir)
            # Warn user since this should not be left on in production code.
            logger.warning(f"Temporary directory '{tmpdir}' not set for deletion.")
            # Set link to current temporary directory.
            try:
                mwcp_current = os.path.join(tempfile.gettempdir(), "mwcp_current")
                if os.path.lexists(mwcp_current):
                    os.unlink(mwcp_current)
                os.symlink(tmpdir, mwcp_current, target_is_directory=True)
            except OSError:
                # We can fail to create a symlink in Windows if "Developer Mode" is not enabled.
                pass
        else:
            context = tempfile.TemporaryDirectory(prefix="mwcp_")

        with context as tmpdir:
            # Fall back to the md5 when the name is missing or sanitizes to a
            # blank/whitespace-only string. Such a name produces an invalid path
            # that cannot be written (for example a name of all spaces on
            # Windows). See #51.
            filename = sanitize_filename(self.name).strip() if self.name else ""
            temp_file = os.path.join(tmpdir, filename or self.md5)
            if extension and not temp_file.endswith(extension):
                temp_file += extension
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

    @functools.lru_cache
    def stack_strings(
            self,
            disassembler: str = None,
            start: int = None,
            min_length: int = 3,
            **config: Unpack[IterContextArgs]
    ) -> List[str]:
        """
        Returns the stack strings for the file.

        :param disassembler: Name of disassembler to use.
        :param start: The address to start tracing stack strings.
            Defaults to tracing all functions in the sample.
        :param min_length: Minimal number of bytes to count as a stack string.
        :param config: Extra emulation arguments passed onto the underlying iter_context_at() call.
        """
        with self.disassembly(disassembler=disassembler) as dis:
            stack_strings = rugosa.find_stack_strings(dis, start, min_length, **config)
            return sorted(set(str(string) for string in stack_strings))

    @functools.lru_cache
    def static_strings(self, disassembler: str = None, min_length: int = 3) -> List[str]:
        """
        Returns the static strings for the file.

        :param disassembler: Name of disassembler to use.
        :param min_length: Minimal number of bytes to count as a static string.
        """
        with self.disassembly(disassembler=disassembler) as dis:
            return [str(string) for string in dis.strings(min_length=min_length)]

    def strings(self, disassembler: str = None, min_length: int = 3) -> List[str]:
        """
        Returns the strings for the file. (static and dynamic)

        :param disassembler: Name of disassembler to use.
        :param min_length: Minimal number of bytes to count as a static string.
        """
        return (
            self.static_strings(disassembler, min_length=min_length)
            + self.stack_strings(disassembler, min_length=min_length)
        )

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
        if not self._architecture:
            if self.pe:
                self._architecture = pefileutils.obtain_architecture_string(pe=self.pe, bitterm=False)
            elif self.elf:
                if (arch := self.elf.get_machine_arch()) != "<unknown>":
                    self._architecture = arch
        return self._architecture

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
    def disassembly(self, disassembler: str = None, report: Report = None, keep=False, **config) -> ContextManager["dragodis.Disassembler"]:
        """
        Produces a Dragodis Disassembler object for the file.
        Dragodis must be installed for this work.

        e.g.
            with self.file_object.disassembly() as dis:
                mnemonic = dis.get_instruction(0x1234).mnemonic

        :param disassembler: Name of the backend disassembler to use.
            (e.g. "ida", "ghidra", or "vivisect")
            If not provided, the disassembler setup in the environment variable
            DRAGODIS_DISASSEMBLER will be used.
            (It is usually recommended to not set the variable so the parser is cross
            compatible with any disassembler Dragodis supports.)
        :param report: Provide the Report object if you want the annotated disassembler project file to
            be added after processing.
            This is usually only recommended if the parser plans to annotate the disassembly. e.g. API resolution
        :param keep: Whether to prevent the temporary directory from being deleted.

        :raises DependencyNotInstalled: If dragodis is not installed.
        """
        in_pytest = "PYTEST_CURRENT_TEST" in os.environ

        if in_pytest and settings.testing.skip_dragodis:
            import pytest
            pytest.skip("Uses Dragodis")

        if not dragodis:
            if in_pytest and settings.testing.skip_missing:
                import pytest
                pytest.skip("Dragodis not installed")
            raise DependencyNotInstalled("Please install Dragodis to use this function.")

        with self.temp_path(keep=keep) as file_path:
            with dragodis.open_program(file_path, disassembler, **config) as dis:
                project_file = dis.project_path
                yield dis

            # After processing we want to save the annotated project file if report was provided.
            if report and project_file.exists():
                if dis.name.casefold() == "ghidra":
                    project_file = pathlib.Path(shutil.make_archive(
                        str(project_file), format="zip", root_dir=project_file
                    ))
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

        :raises DependencyNotInstalled: If kordesii is not installed.
        """
        in_pytest = "PYTEST_CURRENT_TEST" in os.environ

        if in_pytest and settings.testing.skip_kordesii:
            import pytest
            pytest.skip("Uses Kordesii")

        if not kordesii:
            if in_pytest and settings.testing.skip_missing:
                import pytest
                pytest.skip("Kordesii not installed")
            raise DependencyNotInstalled("Please install Kordesii to use this function.")

        if self.data is None:
            raise ValueError(f"FileObject has no data: {self!r}")

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

    def is_archive(self) -> bool:
        """
        Detects if file is an archive (using patool)
        """
        if not patoolib:
            raise DependencyNotInstalled("patool dependency is not installed. Please install mwcp with 'patool' extra.")
        with self.temp_path() as file_path:
            return patoolib.is_archive(file_path)

    def extract_archive(self, extension: str = None, **patool_options) -> Iterable[FileObject]:
        """
        Extracts and yields subfiles within an archive.
        (tip: use is_archive() first to check)

        e.g.
            for subfile in self.file_object.extract_archive():
                if subfile.name.endswith(".bat"):
                    self.dispatcher.add(subfile, description="SuperMalware Loader")
                    break

        WARNING: This uses shell tools on the system though the use of patool (wummel.github.io/patool).

        :param patool_options: Options to pass to patool. (e.g. program="/location/to/7z")

        :raises ValueError: If file is not a valid archive file.
        """
        if not patoolib:
            raise DependencyNotInstalled("patool dependency is not installed. Please install mwcp with 'patool' extra.")
        with self.temp_path(extension=extension) as file_path:
            # Run patool to extract files using appropriate tool.
            output_dir = pathlib.Path(file_path + ".extracted")
            try:
                patoolib.extract_archive(file_path, outdir=str(output_dir), **patool_options)
            except PatoolError as e:
                raise ValueError(e)
            archive, _ = patoolib.get_archive_format(file_path)

            # Walk the output file and yield them as FileObjects
            for path in output_dir.rglob("*"):
                if path.is_file():
                    yield FileObject(path.read_bytes(), name=path.name, derivation=f"{archive} extraction")
