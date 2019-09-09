"""Stores default configuration values."""

import logging
import os
import pkg_resources


import appdirs
from ruamel.yaml import YAML


logger = logging.getLogger(__name__)
yaml = YAML()


class Config(dict):

    CONFIG_FILE_NAME = 'config.yml'
    USER_CONFIG_DIR = appdirs.user_config_dir('mwcp', appauthor=False)

    # Fields which contain a file or directory path.
    PATH_FIELDS = ['LOG_CONFIG_PATH', 'TESTCASE_DIR', 'MALWARE_REPO', 'PARSER_DIR', 'PARSER_CONFIG_PATH']

    def __repr__(self):
        return 'Config({})'.format(super(Config, self).__repr__())

    @property
    def user_path(self):
        """Returns the path to the user config file."""
        # Get user directory.
        cfg_dir = self.USER_CONFIG_DIR
        if not os.path.isdir(cfg_dir):
            os.makedirs(cfg_dir)

        # Create a user copy if it doesn't exist.
        cfg_file_path = os.path.join(cfg_dir, self.CONFIG_FILE_NAME)
        if not os.path.isfile(cfg_file_path):
            with pkg_resources.resource_stream('mwcp.config', self.CONFIG_FILE_NAME) as default_cfg:
                with open(cfg_file_path, 'wb') as fp:
                    fp.write(default_cfg.read())

        # Also copy over log_config.yml
        log_config_path = os.path.join(cfg_dir, 'log_config.yml')
        if not os.path.isfile(log_config_path):
            default_log_cfg = pkg_resources.resource_stream('mwcp.config', 'log_config.yml')
            with open(log_config_path, 'wb') as fp:
                fp.write(default_log_cfg.read())
            default_log_cfg.close()

        return cfg_file_path

    def load(self, file_path=None):
        """Loads configuration file."""
        if not file_path:
            file_path = self.user_path

        with open(file_path, 'r') as fp:
            config = dict(yaml.load(fp))

        # Convert file path into absolute paths.
        directory = os.path.dirname(file_path)
        for key, value in config.items():
            if key in self.PATH_FIELDS:
                value = os.path.expanduser(value)
                value = os.path.expandvars(value)
                value = os.path.join(directory, value)
                value = os.path.abspath(value)
                config[key] = value
        self.update(config)


_config = Config()

# We are going to manually add the fields.json path because
# the fields.json file is not currently designed to be modified.
_config['FIELDS_PATH'] = os.path.abspath(pkg_resources.resource_filename('mwcp.config', 'fields.json'))

