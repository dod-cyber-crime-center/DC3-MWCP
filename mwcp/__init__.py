"""Exposes interface for MWCP."""

import logging

# Add null handler to root logger to avoid "no handler" error when this is used as a library
logging.getLogger().addHandler(logging.NullHandler())


from mwcp.config import _config as config
from mwcp.parser import Parser
from mwcp.file_object import FileObject
from mwcp.registry import (
    register_entry_points, register_parser_directory, register_parser_package,
    iter_parsers, get_parser_descriptions, set_default_source,
    clear as clear_registry,
    clear_default_source,
    ParserNotFoundError
)
from mwcp.runner import Runner
from mwcp.report import Report
from mwcp.dispatcher import Dispatcher, UnidentifiedFile
from mwcp.utils.logutil import setup_logging
from mwcp.core import run, schema
from mwcp.exceptions import *


__version__ = "3.10.1"
