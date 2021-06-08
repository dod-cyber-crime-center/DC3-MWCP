

class MWCPError(Exception):
    """
    Base class for custom exceptions thrown by MWCP.
    """


class UnableToParse(MWCPError):
    """
    This exception can be thrown if a parser that has been correctly identified has failed to parse
    the file and you would like other parsers to be tried.
    """


class ValidationError(MWCPError):
    """
    This exception can be thrown if validation fails when adding metadata.
    """


class ParserNotFoundError(MWCPError):
    """
    This exception gets thrown if a parser can't be found.
    """
