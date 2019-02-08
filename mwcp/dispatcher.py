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
    DESCRIPTION = 'Unidentified file'

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

    def __init__(self, name, author='', description='', parsers=None, greedy=False, default=UnidentifiedFile,
                 output_unidentified=True, overwrite_descriptions=False):
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

        # Dictionary that can be used by parsers to pass variables across parsers.
        # E.g. an encryption key found in the loader to be used by the implant.
        self.knowledge_base = {}

    def identify(self, file_object):
        """
        Determines if this dispatcher is identified to support the given file_object.

        :param file_object: file object to use for identification
        :type file_object: dispatcher.FileObject

        :return bool: Boolean indicating if this dispatcher supports the file_object
        """
        return any(parser.identify(file_object) for parser in self.parsers)

    def add_to_queue(self, file_object):
        """
        Add a FileObject to the FIFO queue for processing.
        :param file_object: a FileObject object requiring processing.
        :return:
        """
        assert isinstance(file_object, FileObject), "Not a FileObject: {!r}".format(file_object)
        file_object.parent = self._current_file_object
        self._fifo_buffer.appendleft(file_object)
        if self._current_file_object:
            logger.info('{} dispatched residual file: {}'.format(
                self._current_file_object.file_name, file_object.file_name))

    def _iter_parsers(self, file_object):
        """
        Generator that detects and yields applicable parsers to run based on given file_object.

        :param FileObject file_object: file object that needs to be identified

        :yields: Identified Parser class or another Dispatcher that can be run
        """
        identified = False
        for parser in self.parsers:
            if parser.identify(file_object):
                logger.info(
                    'File {} identified as {}.'.format(file_object.file_name, parser.DESCRIPTION))
                identified = True
                yield parser

        if not identified:
            if not self._output_unidentified:
                file_object.output_file = False
            # If no parsers match and developer didn't set a description, mark as unidentified file and run
            # default.
            if not file_object.description:
                logger.info('Supplied file {} was not identified.'.format(file_object.file_name))
                if self.default:
                    yield self.default

    def parse(self, file_object, reporter, dispatcher=None):
        """
        Runs dispatcher on given file_object.

        :param FileObject file_object: Object containing data about component file.
        :param mwcp.Reporter reporter: reference to reporter object that executed this parser.
        :param Dispatcher dispatcher: reference to the dispatcher object that called this parse command. (unused)
        :return:
        """
        # TODO: Use reporter to output metadata about initial input file.
        self.add_to_queue(file_object)

        # Pull knowledge_base from previous dispatcher.
        if dispatcher:
            self.knowledge_base.update(dispatcher.knowledge_base)

        while self._fifo_buffer:
            file_object = self._fifo_buffer.pop()

            # Run any applicable parsers.
            for parser in self._iter_parsers(file_object):
                self._current_file_object = file_object
                self._current_parser = parser

                # If a description wasn't set for the file, use the parser's
                if not file_object.description or self._overwrite_descriptions:
                    file_object.description = parser.DESCRIPTION

                # Set parser class used in order to keep a history.
                file_object.parser = parser

                try:
                    parser.parse(file_object, reporter, dispatcher=self)

                except UnableToParse as exception:
                    logger.info(
                        'File {} was misidentified as {}, due to: ({}) '
                        'Trying other parsers...'.format(file_object.file_name, parser.DESCRIPTION, exception))
                    continue

                except Exception:
                    logger.exception('{} dispatch parser failed'.format(parser.name))

                if not self.greedy:
                    break

            # Output the file.
            # NOTE: We don't want to output the file until the very end, since a parser may want to change
            # the file's filename or description.
            file_object.output()
