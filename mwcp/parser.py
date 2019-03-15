import abc
import logging
import six

# This is here for type hints and autocomplete in PyCharm
# noinspection PyUnreachableCode
if False:
    from mwcp import FileObject

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

    def __repr__(cls):
        return '<{}>'.format(cls.name)


@six.add_metaclass(ParserMeta)
class Parser(object):
    """
    Interface for all parser objects.
    Either use this as a base for all component parsers, or
    inherit this class into a customized base class for all parsers.  This class includes some of the required data
    used by various other classes.
    """
    file_object = None  # type: FileObject
    # This is the description that will be given the the file object during output
    # if no description is set in the file_object. This must be overwritten by inherited classes.
    DESCRIPTION = None

    # TODO: Deprecate the AUTHOR field?
    AUTHOR = ''  # Optional

    def __init__(self, file_object, reporter, dispatcher):
        """
        Initializes the Parser.

        :param FileObject file_object: Object containing data about component file.
        :param mwcp.Reporter reporter: reference to reporter object that executed this parser.
        :param Dispatcher dispatcher: reference to the dispatcher object
        """
        if not self.DESCRIPTION:
            raise NotImplementedError('Parser class is missing a DESCRIPTION.')
        self.file_object = file_object
        self.reporter = reporter
        self.dispatcher = dispatcher
        self.logger = logging.getLogger('.'.join([self.__class__.__module__, self.__class__.__name__]))

    @classmethod
    def iter_subclasses(cls):
        """Yields all classes that inherit from this class."""
        for subclass in cls.__subclasses__():
            yield subclass
            for _subclass in subclass.iter_subclasses():
                yield _subclass

    @classmethod
    def identify(cls, file_object):
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
        """
        logger.warning("Missing identify() function for: {}.{}".format(cls.__module__, cls.__name__))
        return True  # Default to True to keep backwards compatibility for legacy parsers.

    @classmethod
    def parse(cls, file_object, reporter, dispatcher=None):
        """
        Runs parser on given file_object.

        :param FileObject file_object: Object containing data about component file.
        :param mwcp.Reporter reporter: reference to reporter object that executed this parser.
        :param Dispatcher dispatcher: reference to the dispatcher object. (if used)
        :return:
        """
        # TODO: Use reporter to output metadata about initial input file.
        if dispatcher:
            parser_object = cls(file_object, reporter, dispatcher)
            parser_object.run()

        # If dispatcher isn't provided, create a dummy one containing only this parser.
        else:
            from mwcp import Dispatcher  # Must import here to avoid cyclic import.
            dispatcher = Dispatcher(cls.name, author=cls.AUTHOR, description=cls.DESCRIPTION, parsers=[cls])
            dispatcher.parse(file_object, reporter)

    def run(self):
        """
        This function can be overwritten. It is called to run the parser.
        You don't have to overwrite this method if you only want to identify/output the file.
        :return:
        """
        pass
