"""
Implements FileObject class used to provide an interface for the file being parsed.
"""

import hashlib
import io
import logging
import os

from mwcp.utils import elffileutils, pefileutils

try:
    import kordesii
except ImportError:
    # Kordesii support is optional.
    kordesii = None

from mwcp.utils.stringutils import convert_to_unicode

logger = logging.getLogger(__name__)



class FileObject(object):
    """
    This class represents a file object which is to be parsed by the MWCP parser.
    It is pushed into the dispatcher queue for processing.
    """

    def __init__(
            self, file_data, reporter, pe=None, file_name=None, def_stub=None,
            description=None, output_file=True, use_supplied_fname=True, use_arch=False,
            ext='.bin'):
        """
        Initializes the FileObject.

        :param bytes file_data: Data for the file.
        :param pefile.PE pe: PE object for the file.
        :param mwcp.Reporter reporter: MWCP reporter.
        :param str file_name: File name to use if file is not a PE or use_supplied_fname was specified.
        :param str description: Description of the file object.
        :param bool output_file: Boolean indicating if file should be outputted when the dispatcher process the file.
        :param bool use_supplied_fname: Boolean indicating if the file_name should be used even if the file is a PE.
        :param str def_stub: def_stub argument to pass to obtain_original_filename()
        :param bool use_arch: use_arch argument to pass to obtain_original_filename()
        :param str ext: default extension to use if not determined from pe file.
        """
        # Ensure we are getting a bytes string. Libraries like pefile depend on this.
        if not isinstance(file_data, bytes):
            raise TypeError('file_data must be a bytes string.')

        self._file_path = None
        self._md5 = None
        self._sha1 = None
        self._sha256 = None
        self._stack_strings = None
        self._resources = None
        self._elf = None
        self._elf_attempt = False
        self.output_file = output_file
        self._outputted_file = False
        self._kordesii_cache = {}
        self.parent = None   # Parent FileObject from which FileObject was extracted from (this is set externally).
        self.parser = None   # This will be set by the dispatcher.
        self.file_data = file_data
        self.reporter = reporter
        self.description = description
        self.knowledge_base = {}

        self.pe = pe or pefileutils.obtain_pe(file_data)

        use_supplied_fname = use_supplied_fname or not self.pe

        if file_name and use_supplied_fname:
            self._file_name = file_name
        else:
            self._file_name = pefileutils.obtain_original_filename(
                def_stub or self.md5, pe=self.pe, use_arch=use_arch, ext=ext)
        self._file_name = convert_to_unicode(self._file_name)

    def __enter__(self):
        """
        This allows us to use the file_data as a file-like object when used as a context manager.

        e.g.
            >> file_object = FileObject('hello world', None)
            >> with file_object as fo:
            ..     _ = fo.seek(6)
            ..     print fo.read()
            world
        """
        self._open_file = io.BytesIO(self.file_data)
        return self._open_file

    def __exit__(self, *args):
        self._open_file.close()

    # TODO: Deprecate "file_data" name in exchange for "data"?
    @property
    def data(self):
        """Just an alias for file_data"""
        return self.file_data

    @property
    def elf(self):
        """Returns elftools.ELFFile object or None if not an ELF file."""
        if not self._elf and not self._elf_attempt:
            self._elf_attempt = True
            self._elf = elffileutils.obtain_elf(self.file_data)
        return self._elf

    # TODO: Deprecate "file_name" name in exhange for "name"?
    @property
    def file_name(self):
        return self._file_name

    @file_name.setter
    def file_name(self, value):
        # If someone changes the name, record the rename.
        value = convert_to_unicode(value)
        if self._file_name != value:
            logger.info('Renamed {} to {}'.format(self._file_name, value))
        self._file_name = value

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
            self._md5 = hashlib.md5(self.file_data).hexdigest()
        return self._md5

    @property
    def sha1(self):
        """
        Returns sha1 hash of file.
        :return: hash of the file as a hex string
        """
        if not self._sha1:
            self._sha1 = hashlib.sha1(self.file_data).hexdigest()
        return self._sha1

    @property
    def sha256(self):
        """
        Returns sha256 hash of file.
        :return: hash of the file as a hex string
        """
        if not self._sha256:
            self._sha256 = hashlib.sha256(self.file_data).hexdigest()
        return self._sha256

    @property
    def file_path(self):
        """
        Returns a full file path to the file object.
        This is useful for when you want to use this file on libraries which require
        a file path instead of data or file-like object (e.g. cabinet).
        Always create a temporary file, this avoids issues where the identify function requires the file_path and
        the file would be output before a description is set.
        """
        if not self._file_path:
            safe_file_name = convert_to_unicode(self.md5)
            file_path = os.path.join(self.reporter.managed_tempdir, safe_file_name)
            with open(file_path, 'wb') as file_object:
                file_object.write(self.file_data)
            self._file_path = file_path

        return self._file_path

    @file_path.setter
    def file_path(self, value):
        """
        Setter for the file_path attribute. This is used if an external entity can
        provided a valid file_path.
        """
        self._file_path = value

    @property
    def stack_strings(self):
        """
        Returns the stack strings for the file.
        """
        if not self._stack_strings:
            kordesii_reporter = self.run_kordesii_decoder('stack_string')
            self._stack_strings = kordesii_reporter.get_strings()
        return self._stack_strings

    @property
    def resources(self):
        """Returns a list of the PE resources for the given file."""
        if self.pe and not self._resources:
            self._resources = list(pefileutils.iter_rsrc(self.pe))
        return self._resources

    @property
    def is_64bit(self):
        """
        Evaluates whether the file is a 64 bit pe file.

        :return: True if 64-bit, False if 32-bit, None if could not be determined.
        """
        if not self.pe:
            return None
        return pefileutils.is_64bit(pe=self.pe)

    def output(self):
        """
        Outputs FileObject instance to reporter it it hasn't already been outputted.
        """
        # Output file if we are allowed to and the file hasn't already been outputted.
        if self.output_file and not self._outputted_file:
            self.reporter.output_file(
                data=self.file_data, filename=self.file_name or '', description=self.description or '')
            self._outputted_file = True

    def run_kordesii_decoder(self, decoder_name, warn_no_strings=True, decoderdir=None):
        """
        Run the specified kordesii decoder against the file data.  The reporter object is returned
        and can be accessed as necessary to obtain output files, etc.

        :param decoder_name: name of the decoder to run
        :param warn_no_strings: Whether to produce a warning if no string were found.
        :param decoderdir: Custom decoder directory to use instead of the default.

        :return: Instance of the kordesii_reporter.

        :raises RuntimeError: If kordesii is not installed.
        """
        if not kordesii:
            raise RuntimeError('Please install kordesii to use this function.')

        # Pull from cache if we already ran this decoder.
        if decoder_name in self._kordesii_cache:
            return self._kordesii_cache[decoder_name]

        logger.info('Running {} kordesii decoder on file {}.'.format(decoder_name, self.file_name))
        kordesii_reporter = kordesii.Reporter(
            decoderdir=decoderdir, base64outputfiles=True)

        kordesii_reporter.run_decoder(decoder_name, data=self.file_data, log=True)

        if warn_no_strings:
            decrypted_strings = kordesii_reporter.get_strings()
            if not decrypted_strings:
                # Not necessarily a bad thing, the decoder might be used for something else.
                logger.info(
                    'No decrypted strings were returned by the decoder for file {}.'.format(self.file_name))

        # Cache results
        self._kordesii_cache[decoder_name] = kordesii_reporter

        return kordesii_reporter
