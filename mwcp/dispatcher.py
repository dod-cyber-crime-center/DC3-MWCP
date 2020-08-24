"""
Implements a data pump for extracted file data which allows for
more robust file identification, reporting, and objectifying
content to ease maintenance.
"""

import logging
from collections import deque

from mwcp.file_object import FileObject
from mwcp.parser import Parser

logger = logging.getLogger(__name__)


class UnableToParse(Exception):
    """
    This exception can be thrown if a parser that has been correctly identified has failed to parse
    the file and you would like other parsers to be tried.
    """

    pass


class UnidentifiedFile(Parser):
    """Describes an unidentified file. This parser will hit on any FileObject."""

    DESCRIPTION = "Unidentified file"

    @classmethod
    def identify(cls, file_object):
        """
        Identifies an unidentified file... which means this is always True.

        :param file_object: dispatcher.FileObject object
        :return: Boolean indicating idenification
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

    def __init__(
        self,
        name,
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
        # TODO: Deprecate the author attribute?
        self.AUTHOR = author
        self.DESCRIPTION = description  # In all caps to match Parser interface
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

    def identify(self, file_object):
        """
        Determines if this dispatcher is identified to support the given file_object.

        :param file_object: file object to use for identification
        :type file_object: dispatcher.FileObject

        :return bool: Boolean indicating if this dispatcher supports the file_object
        """
        return any(parser.identify(file_object) for parser in self.parsers)

    def add_to_queue(self, file_object: FileObject, parent: FileObject = None):
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

    def _iter_parsers(self, file_object):
        """
        Generator that detects and yields applicable parsers to run based on given file_object.

        :param FileObject file_object: file object that needs to be identified

        :yields: Identified Parser class or another Dispatcher that can be run
        """
        for parser in self.parsers:
            logger.debug(u"Identifying {} with {!r}.".format(file_object.name, parser))
            if parser.identify(file_object):
                if isinstance(parser, Dispatcher):
                    # Parser is a group, change wording
                    logger.info(f"File {file_object.name} identified with {parser.DESCRIPTION} parser.")
                else:
                    logger.info(f"File {file_object.name} identified as {parser.DESCRIPTION}.")
                logger.debug(u"{} identified with {!r}".format(file_object.name, parser))
                yield parser

    def _parse(self, file_object, parser, reporter):
        """
        Parse given file_object with given sub parser

        :raises UnableToParse: If the subparser raised an error.
        """
        self._current_file_object = file_object
        self._current_parser = parser

        # If a description wasn't set for the file, use the parser's
        # (But ignore setting it for sub dispatchers)
        if (not file_object.description or self._overwrite_descriptions) and not isinstance(parser, Dispatcher):
            file_object.description = parser.DESCRIPTION

        # Set parser class used in order to keep a history.
        file_object.parser = parser

        try:
            parser.parse(file_object, reporter, dispatcher=self)
        except UnableToParse as exception:
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

    def parse(self, file_object, reporter, dispatcher=None):
        """
        Runs dispatcher on given file_object.

        :param FileObject file_object: Object containing data about component file.
        :param mwcp.Reporter reporter: reference to reporter object that executed this parser.
        :param Dispatcher dispatcher: reference to the parent dispatcher object that called this parse command.
            (None if this dispatcher is the root)
        :return:
        """
        # TODO: Use reporter to output metadata about initial input file.
        self.add_to_queue(file_object)

        # Pull knowledge_base from previous dispatcher.
        if dispatcher:
            self.knowledge_base = dispatcher.knowledge_base

        first = True
        while self._fifo_buffer:
            file_object = self._fifo_buffer.pop()

            # If this dispatcher is embedded, simply pass any dispatched files to the parent.
            if self._embedded and dispatcher and not first:
                dispatcher.add_to_queue(file_object)
                continue

            first = False
            identified = False

            try:
                unable_to_parse_error = None
                # Run any applicable parsers.
                for parser in self._iter_parsers(file_object):
                    try:
                        self._parse(file_object, parser, reporter)
                    except UnableToParse as e:
                        unable_to_parse_error = e
                        continue
                    identified = True
                    if not self.greedy:
                        break
                if identified:
                    continue
                elif unable_to_parse_error and dispatcher:
                    # Pass UnableToParse exception up the chain to notify parent
                    raise unable_to_parse_error

                # Give it to the parent dispatcher if we can't identify it.
                if dispatcher:
                    dispatcher.add_to_queue(file_object)
                    continue

                # If no parsers match and developer didn't set a description,
                # mark as unidentified file and run default.
                if not file_object.description:
                    logger.info(u"Supplied file {} was not identified.".format(file_object.file_name))
                    if self.default:
                        try:
                            self._parse(file_object, self.default, reporter)
                        except UnableToParse:
                            pass

            finally:
                # Output the file if we identified it or we are the root.
                # NOTE: We don't want to output the file until the very end, since a parser may want to change
                # the file's filename or description.
                if identified or (not dispatcher and self._output_unidentified):
                    file_object.output()
