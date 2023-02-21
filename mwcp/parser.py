import abc
import logging
from typing import TYPE_CHECKING, Union, Tuple, Any
import warnings

# This is here for type hints and autocomplete in PyCharm
# noinspection PyUnreachableCode
if TYPE_CHECKING:
    from mwcp import FileObject, Report

logger = logging.getLogger(__name__)


# A way to create a class properties
# (Adding ABCMeta so, parsers have the freedom to use it.)
class ParserMeta(abc.ABCMeta):
    @property
    def name(cls):
        try:
            return cls._name
        except AttributeError:
            return cls.__name__

    @name.setter
    def name(cls, value):
        cls._name = value

    @property
    def source(cls):
        try:
            return cls._source
        except AttributeError:
            module, _, _ = cls.__module__.partition(".")
            return module

    @source.setter
    def source(cls, value):
        cls._source = value

    def __repr__(cls):
        return "<{}>".format(cls.name)


class Parser(metaclass=ParserMeta):
    """
    Interface for all parser objects.
    Either use this as a base for all component parsers, or
    inherit this class into a customized base class for all parsers.  This class includes some of the required data
    used by various other classes.
    """

    file_object = None  # type: FileObject
    # This is the description that will be given to the file object during output
    # if no description is set in the file_object. This must be overwritten by inherited classes.
    DESCRIPTION = None
    # This is a tuple of tags that will be added to the file object after identification.
    TAGS = ()

    # TODO: Deprecate the AUTHOR field?
    AUTHOR = ""  # Optional

    def __init__(self, file_object, report, dispatcher):
        """
        Initializes the Parser.

        :param FileObject file_object: Object containing data about component file.
        :param mwcp.Report report: Report object to be filled in.
        :param Dispatcher dispatcher: reference to the dispatcher object
        """
        if not self.DESCRIPTION:
            raise NotImplementedError("Parser class is missing a DESCRIPTION.")
        self.file_object = file_object
        self.report = report
        self.dispatcher = dispatcher
        self.logger = logging.getLogger(".".join([self.__class__.__module__, self.__class__.__name__]))

    @property
    def reporter(self) -> "Report":
        warnings.warn(
            "reporter has been renamed to report and is now an instance of mwcp.Report",
            DeprecationWarning
        )
        return self.report

    @property
    def knowledge_base(self) -> dict:
        """
        Convenience function for getting knowledge_base.
        """
        return self.report.knowledge_base

    @classmethod
    def get_logger(cls):
        return logging.getLogger(".".join([cls.__module__, cls.__name__]))

    @classmethod
    def iter_subclasses(cls):
        """Yields all classes that inherit from this class."""
        for subclass in cls.__subclasses__():
            yield subclass
            for _subclass in subclass.iter_subclasses():
                yield _subclass

    @classmethod
    def identify(cls, file_object: "FileObject") -> Union[bool, Tuple[bool, Any]]:
        """
        Determines if this parser is identified to support the given file_object.
        This function must be overwritten in order to support identification.

        The passed in file_object may be modified at this time to provide
        a new file_name or description.
        (Be aware, that this change will be in affect for future parsers.
        Therefore, don't change it if you are returning False or the dispatcher is in greedy mode.)

        :param file_object: file object to use for identification
        :type file_object: dispatcher.FileObject

        :return bool: Boolean indicating if this parser supports the file_object
            Extra arguments to pass into the run() function can also be provided.
        """
        logger.warning("Missing identify() function for: {}.{}".format(cls.__module__, cls.__name__))
        return True  # Default to True to keep backwards compatibility for legacy parsers.

    @staticmethod
    def unpack_identify(result) -> Tuple[bool, Any]:
        """
        Helper function to normalize identify results to always produce a tuple of identification result and extras.
        """
        if isinstance(result, tuple) and isinstance(result[0], bool):
            identified, *rest = result
            rest = tuple(rest)
        else:
            identified = bool(result)
            rest = tuple()
        return (identified, *rest)

    @classmethod
    def parse(cls, file_object, report, *run_args, dispatcher=None):
        """
        Runs parser on given file_object.

        :param FileObject file_object: Object containing data about component file.
        :param mwcp.Report report: reference to report object used to report new metadata.
        :param run_args: Extra arguments returned from identify() to pass to run() function.
        :param Dispatcher dispatcher: reference to the dispatcher object. (if used)
        :return:
        """
        if dispatcher:
            report.set_file(file_object)
            parser_object = cls(file_object, report, dispatcher)
            parser_object.run(*run_args)

        # If dispatcher isn't provided, create a dummy one containing only this parser.
        # This is necessary to ensure identification is run first.
        else:
            from mwcp import Dispatcher  # Must import here to avoid cyclic import.

            dispatcher = Dispatcher(cls.name, cls.source, author=cls.AUTHOR, description=cls.DESCRIPTION, parsers=[cls])
            dispatcher.parse(file_object, report, *run_args)

    def run(self, *args):
        """
        This function can be overwritten. It is called to run the parser.
        You don't have to overwrite this method if you only want to identify/output the file.
        :return:
        """
        pass
