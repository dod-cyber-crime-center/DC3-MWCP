"""Stores default configuration values."""

import os

_directory = os.path.dirname(__file__)

FIELDS_PATH = os.path.join(_directory, 'fields.json')
LOG_CONFIG_PATH = os.path.join(_directory, 'log_config.yml')
PARSER_CONFIG_PATH = os.path.join(_directory, 'parser_config.yml')
