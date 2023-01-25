"""
Implements a data pump for extracted file data which allows for
more robust file identification, reporting, and objectifying
content to ease maintenance.
"""

import logging
import warnings
from collections import deque

from mwcp import metadata
from mwcp.exceptions import UnableToParse
from mwcp.file_object import FileObject
from mwcp.parser import Parser
from mwcp.report import Report

logger = logging.getLogger(__name__)


class UnidentifiedFile(Parser):
    """Describes an unidentified file. This parser will hit on any FileObject."""

    DESCRIPTION = "Unidentified file"

    @classmethod
    def identify(cls, file_object):
        """
        Identifies an unidentified file... which means this is always True.

        :param file_object: dispatcher.FileObject object
        :return: Boolean indicating identification
        """
        return True


# NOTE: This object is duck typed to look like a Parser object to allow recursion.
# TODO: Create abstract inteface for these two.
class Dispatcher(object):
    # TODO: Rewrite this documentation.
    """
    This class will continuously process items that are in the queue.  When the queue is empty,
    this will ultimately signal that processing is complete and the script will terminate.
    This class will process the items using the supplied list of Parser classes provided.

    This class can be used as a mixin along with the Parser class or
    can be initialized by itself.
    When used as a mixin, the dispatcher will automatically add the file in the reporter
    to the queue and run dispatch() when run() is called.
    """

    # Caches results for identification to improve speed.
    _identify_cache = {}

    def __init__(
        self,
        name,
        source,
        author="",
        description="",
        parsers=None,
        greedy=False,
        default=UnidentifiedFile,
        output_unidentified=True,
        overwrite_descriptions=False,
        embedded=False,
    ):
        """
        Initializes the Dispatcher with the given parsers to run.

        :param str name: Unique name to give to this group of parsers.
        :param str source: Name of source this group comes from.
        :param str author: Author of the parser.
        :param str description: Description of the parser.
        :param list parsers: A list of parser classes (or other dispatchers) to use for detection and running.
            Order of this list is the order the Dispatcher will perform its identification.
            If not provided, it will default to an empty list.
        :param bool greedy: By default, the dispatcher will only run on the first parser it detects
            to be a valid parser. If greedy is set to true, the dispatcher will try all parsers
            even if a previous parser was successful.
        :param ComponentParser default: The Parser class to default to if no parsers in the parsers list
            has identified it. If set to None, no parser will be run as default.
            (By default, the dispatcher.UnidentifiedFile will be run.)
        :param bool output_unidentified: Whether to output files that have not been identified by
            any parsers.
        :param bool overwrite_descriptions: Whether to allow dispatcher to overwrite any previous
            set description with the parser's
        :param bool embedded: If True, all dispatched files will be passed up to the parent
            dispatcher instead of being processed locally.
            Ie, this is the equivalent of embedding the listed parsers directly into the parent's list.
        """
        self.name = name
        self.source = source
        # TODO: Deprecate the author attribute?
        self.AUTHOR = author
        self.DESCRIPTION = description  # In all caps to match Parser interface
        self.TAGS = ()
        self.parsers = parsers or []
        self.greedy = greedy
        self.default = default
        self._fifo_buffer = deque()
        self._current_file_object = None
        self._current_parser = None
        self._output_unidentified = output_unidentified
        self._overwrite_descriptions = overwrite_descriptions
        self._embedded = embedded

        # Dictionary that can be used by parsers to pass variables across parsers.
        # E.g. an encryption key found in the loader to be used by the implant.
        self.knowledge_base = {}

    def __repr__(self):
        return "{}({})".format(self.name, ", ".join(repr(parser) for parser in self.parsers))

    @classmethod
    def _cleanup(cls):
        # Clear identify cache to prevent memory leaking.
        cls._identify_cache = {}

    def identify(self, file_object):
        """
        Determines if this dispatcher is identified to support the given file_object.

        :param file_object: file object to use for identification
        :type file_object: dispatcher.FileObject

        :return bool: Boolean indicating if this dispatcher supports the file_object
        """
        return any(self._identify_parsers(file_object))

    def add_to_queue(self, file_object: FileObject, parent: FileObject = None):
        warnings.warn(
            "add_to_queue() has been renamed to add()",
            DeprecationWarning
        )
        self.add(file_object, parent=parent)

    def add(self, file_object: FileObject, parent: FileObject = None):
        """
        Add a FileObject to the FIFO queue for processing.
        :param file_object: a FileObject object requiring processing.
        :param parent: original parent for given file_object.
            If not provided, the parent is assumed to be the file being currently
            processed. (which should be true most of the time)

        :return:
        """
        if not parent:
            parent = self._current_file_object
        assert isinstance(file_object, FileObject), "Not a FileObject: {!r}".format(file_object)

        # FIXME: Disabled for now.
        # if parent == file_object:
        #     # Letting this be info instead of warning, since it is not necessarily
        #     # a problem. (e.g. deobfuscation parser runs on already deobfuscated file)
        #     logger.info(f"{parent.name} dispatched itself, ignoring...")
        #     return

        # If we already have a parent, this means this file is trickling up from a sub-dispatcher.
        # Don't duplicate logs or change the parent.
        if not file_object.parent:
            file_object.parent = parent
            if parent:
                parent.children.append(file_object)
                logger.info(f"{parent.name} dispatched residual file: {file_object.name}")
                if file_object.description:
                    logger.info(f"File {file_object.name} described as {file_object.description}")

        self._fifo_buffer.appendleft(file_object)

    def _identify_parsers(self, file_object: FileObject):
        """
        Generator that detects and yields identified parsers to run based on given file_object.

        :param file_object: file object that needs to be identified

        :yields: Identified Parser class or another Dispatcher that can be run
        """
        for parser in self.parsers:
            logger.debug(u"Identifying {} with {!r}.".format(file_object.name, parser))

            # First see if result has been cached.
            key = (parser, file_object)
            if key in self._identify_cache:
                ret = self._identify_cache[key]
            else:
                ret = parser.identify(file_object)
                self._identify_cache[key] = ret

            if isinstance(ret, tuple) and isinstance(ret[0], bool):
                identified, *rest = ret
                rest = tuple(rest)
            else:
                identified = ret
                rest = tuple()

            if identified:
                yield parser, rest

    def _parse(self, file_object, parser, report, *run_args):
        """
        Parse given file_object with given sub parser

        :raises UnableToParse: If the subparser raised an error.
        """
        self._current_file_object = file_object
        self._current_parser = parser

        # If a description wasn't set for the file, use the parser's
        # (But ignore setting it for sub dispatchers)
        orig_description = file_object.description
        if (not file_object.description or self._overwrite_descriptions) and not isinstance(parser, Dispatcher):
            file_object.description = parser.DESCRIPTION

        # Add tags to the file.
        orig_tags = set(file_object.tags)
        for tag in parser.TAGS:
            file_object.add_tag(tag)

        # Set parser class used in order to keep a history.
        orig_parser = file_object.parser
        file_object.parser = parser

        try:
            parser.parse(file_object, report, *run_args, dispatcher=self)
        except UnableToParse as exception:
            # Undo setting parser metadata to file if we misidentify.
            file_object.description = orig_description
            file_object.tags = orig_tags
            file_object.parser = orig_parser

            # Mark identify cache as failure, so we don't need to go through this again.
            self._identify_cache[(parser, file_object)] = False

            # Log to user before reraising.
            if isinstance(parser, Dispatcher):
                # Parser is a group, change wording
                logger.info(
                    f"File {file_object.file_name} was misidentified with {parser.DESCRIPTION} parser, due to: "
                    f"({exception}) Trying other parsers..."
                )
            else:
                logger.info(
                    f"File {file_object.file_name} was misidentified as {parser.DESCRIPTION}, due to: "
                    f"({exception}) Trying other parsers..."
                )
            raise
        except Exception:
            logger.exception(u"{} dispatch parser failed".format(parser.name))

    def parse(self, file_object: FileObject, report: Report, *run_args, dispatcher: "Dispatcher" = None):
        """
        Runs dispatcher on given file_object.

        :param file_object: Object containing data about component file.
        :param report: Report object to be filled in.
        :param run_args: Extra arguments returned from identify() to pass to run() function.
        :param dispatcher: reference to the parent dispatcher object that called this parse command.
            (None if this dispatcher is the root)
        :return:
        """
        parent = dispatcher
        orig_file_object = file_object
        self.add(file_object)

        # Pull knowledge_base from previous dispatcher.
        if parent:
            self.knowledge_base = parent.knowledge_base

        while self._fifo_buffer:
            file_object = self._fifo_buffer.pop()
            first = file_object is orig_file_object

            # If this dispatcher is embedded, simply pass any dispatched files to the parent.
            if self._embedded and parent and not first:
                parent.add(file_object)
                continue

            identified = False
            unable_to_parse_error = None

            try:
                # If file has already been parsed, don't bother running it again.
                # (This also helps with cyclic loops)
                # FIXME: Disabled until we can fix bug with greedy parsers.
                if file_object.md5 in report.parsed_files and False:
                    logger.info(f"File {file_object.name} has already been parsed. Ignoring...")
                    # Copy file description from the already parsed version and mark as duplicate.
                    parsed_file = report.parsed_files[file_object.md5]
                    file_object.description = parsed_file.description
                    file_object.add_tag("duplicate")
                    continue

                # Run applicable parsers.
                for parser, _run_args in self._identify_parsers(file_object):
                    if isinstance(parser, Dispatcher):
                        # Parser is a group, change wording
                        logger.info(f"File {file_object.name} identified with {parser.DESCRIPTION} parser.")
                    else:
                        logger.info(f"File {file_object.name} identified as {parser.DESCRIPTION}.")
                    logger.debug(f"{file_object.name} identified with {parser!r}")

                    try:
                        self._parse(file_object, parser, report, *_run_args)
                    except UnableToParse as e:
                        unable_to_parse_error = e
                        continue
                    identified = True
                    if not self.greedy:
                        break

                if identified:
                    continue

                # If this is the first file in the buffer and we get UnableToParse, that means one of the parsers
                # that identified it to use this dispatcher instance is wrong.
                # Propogate that up.
                if unable_to_parse_error and parent and first:
                    raise unable_to_parse_error

                # Give it to the parent dispatcher if we can't identify it.
                if parent:
                    parent.add(file_object)
                    continue

                # If no parsers match and developer didn't set a description,
                # mark as unidentified file and run default.
                if not file_object.description:
                    logger.info(f"Supplied file {file_object.name} was not identified.")
                    if self.default:
                        try:
                            self._parse(file_object, self.default, report)
                        except UnableToParse:
                            pass

            finally:
                # Report the file as residual if we identified it or we are the root parser.
                # NOTE: We don't want to report the file until the very end, since a parser may want to change
                # the file's filename or description.
                if identified or (not parent and self._output_unidentified):
                    if file_object.output_file:
                        # Temporarily set current file back to parent so residual file is
                        # reported correctly.
                        report.set_file(file_object.parent)
                        report.add(metadata.File.from_file_object(file_object))
                        report.set_file(file_object)

                    if file_object.md5 not in report.parsed_files:
                        report.parsed_files[file_object.md5] = file_object

                # Cleanup any temporary files the file_object may have created.
                file_object._clear_temp_path_ctx()
