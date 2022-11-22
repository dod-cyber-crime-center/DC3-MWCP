"""Stores default configuration values."""

import logging
import os
import pathlib
import pkg_resources


import appdirs
from ruamel.yaml import YAML


logger = logging.getLogger(__name__)
yaml = YAML()


class Config(dict):

    CONFIG_FILE_NAME = "config.yml"
    USER_CONFIG_DIR = pathlib.Path(appdirs.user_config_dir("mwcp"))

    # Fields which contain a file or directory path.
    PATH_FIELDS = ["LOG_CONFIG_PATH", "TESTCASE_DIR", "MALWARE_REPO", "PARSER_DIR", "PARSER_CONFIG_PATH", "YARA_REPO"]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # We are going to manually add the fields.json path because
        # the fields.json file is not currently designed to be modified.
        self["FIELDS_PATH"] = os.path.abspath(pkg_resources.resource_filename("mwcp.config", "fields.json"))

    def __repr__(self):
        return f"Config({super().__repr__()})"

    def clear(self):
        """Clears config (and re-adds FIELDS_PATH)"""
        super().clear()
        self.__init__()

    @property
    def user_config_dir(self) -> pathlib.Path:
        cfg_dir = self.USER_CONFIG_DIR
        cfg_dir.mkdir(parents=True, exist_ok=True)
        return cfg_dir

    @property
    def user_path(self) -> pathlib.Path:
        """Returns the path to the user config file."""
        # Get user directory.
        cfg_dir = self.user_config_dir

        # Create a user copy if it doesn't exist.
        cfg_file_path = cfg_dir / self.CONFIG_FILE_NAME
        if not cfg_file_path.exists():
            with pkg_resources.resource_stream("mwcp.config", self.CONFIG_FILE_NAME) as default_cfg:
                with open(cfg_file_path, "wb") as fp:
                    fp.write(default_cfg.read())

        # Also copy over log_config.yml
        log_config_path = cfg_dir / "log_config.yml"
        if not log_config_path.exists():
            with pkg_resources.resource_stream("mwcp.config", "log_config.yml") as default_log_cfg:
                with open(log_config_path, "wb") as fp:
                    fp.write(default_log_cfg.read())

        return cfg_file_path

    @property
    def pytest_cache_dir(self) -> pathlib.Path:
        return self.user_config_dir / ".pytest_cache"

    def load(self, file_path=None):
        """Loads configuration file."""
        if not file_path:
            file_path = self.user_path

        # Convert str file_path to maintain backwards compatibility with previous function definition
        if isinstance(file_path, str):
            file_path = pathlib.Path(file_path)

        with open(file_path, "r") as fp:
            config = dict(yaml.load(fp))

        # Convert file path into absolute paths.
        directory = str(file_path.parent)
        for key, value in config.items():
            if key in self.PATH_FIELDS:
                value = os.path.expanduser(value)
                value = os.path.expandvars(value)
                value = os.path.join(directory, value)
                value = os.path.abspath(value)
                config[key] = value
        self.update(config)


_config = Config()
