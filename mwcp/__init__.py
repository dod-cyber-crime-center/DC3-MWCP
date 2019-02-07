"""Exposes interface for MWCP."""

import logging

# Add null handler to root logger to avoid "no handler" error when this is used as a library
logging.getLogger().addHandler(logging.NullHandler())


from mwcp.parser import Parser
from mwcp.file_object import FileObject
from mwcp.registry import (
    register_entry_points, register_parser_directory, register_parser_package,
    iter_parsers, get_parser_descriptions, set_default_source, clear_default_source)
from mwcp.reporter import Reporter
from mwcp.resources import techanarchy_bridge
from mwcp.dispatcher import Dispatcher, UnableToParse, UnidentifiedFile
from mwcp.utils.logutil import setup_logging
