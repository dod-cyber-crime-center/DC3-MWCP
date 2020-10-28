"""Utilities for setting up logging."""
import copy
import errno
import logging.config
import logging.handlers
import multiprocessing as mp
import os
import platform
import sys
import threading
import traceback
import warnings
from collections import deque

import appdirs
import yaml

import mwcp

# Queue used to send over log messages from child to main process.
# (See mwcp.utils.multi_proc for its use.)
mp_queue = mp.Queue()


class LevelCharFilter(logging.Filter):
    """Logging filter used to add a 'level_char' format variable."""

    def filter(self, record):
        if record.levelno >= logging.ERROR:
            record.level_char = "!"
        elif record.levelno >= logging.WARN:
            record.level_char = "-"
        elif record.levelno >= logging.INFO:
            record.level_char = "+"
        elif record.levelno >= logging.DEBUG:
            record.level_char = "*"
        else:
            record.level_char = " "
        return True


class MPRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
    Handle the uncommon case of the log attempting to roll over when
    another process has the log open. This only happens on Windows, and
    the log ends up being a handful of KBs greater than 1024. Entries
    are still written, and the rollover happens if/when the MainProcess is
    the only process with the log file open.
    """

    def __init__(self, filename, **kwargs):
        # Expand and variables and home directories and make path if it doesn't exist.
        filename = os.path.expandvars(os.path.expanduser(filename))

        # If path is relative, add to standard log directory.
        if not os.path.isabs(filename):
            filename = os.path.join(appdirs.user_log_dir("mwcp", appauthor=False), filename)

        directory = os.path.dirname(filename)
        if not os.path.exists(directory):
            os.makedirs(directory)
        super(MPRotatingFileHandler, self).__init__(filename, **kwargs)

    def doRollover(self):
        """
        Attempt to roll over to the next log file. If the current file
        is locked (Windows issue), keep writing to the original file until
        it is unlocked.

        :return:
        """
        try:
            super(MPRotatingFileHandler, self).doRollover()
        except OSError as e:
            if not (sys.platform == "win32" and e.errno == errno.EACCES):
                raise


class MPChildHandler(logging.Handler):
    """
    Simple handler for child processes.

    Ensures pickle-ability and sends the record entry to the queue.
    """

    def __init__(self, log_queue):
        super(MPChildHandler, self).__init__()
        self.queue = log_queue

    def emit(self, record):
        if record.exc_info:
            record.exc_text = "".join(traceback.format_exception(*record.exc_info))
            record.exc_info = None

        self.queue.put(record)


class ListHandler(logging.Handler):
    """
    Log to a list, with an optional maximum number of records to store.

    Full records are available with the `records` property, and messages (i.e.
    the text of the log entry) at available with the `messages` property.
    """

    def __init__(self, entries=None):
        """
        Behaves essentially identical to any other handler.

        The only option is max_entries, to specify the max number of log
        entries kept. By default, no limit.

        :param int entries: Maximum number of records to store.
        """
        super(ListHandler, self).__init__()

        self._deque = deque(maxlen=entries)

    def __copy__(self):
        new_handler = ListHandler()
        # Actually copy the deque, otherwise we'll get double entries
        new_handler._deque = copy.copy(self._deque)
        return new_handler

    def emit(self, record):
        msg = self.format(record)
        record.formatted_msg = msg
        self._deque.append(record)

    def clear(self):
        return self._deque.clear()

    @property
    def records(self):
        """
        List of the last `max_entries` records logged.
        """
        return list(self._deque)

    @property
    def messages(self):
        """
        List of the last `max_entries` formatted messages logged.
        """
        return [record.formatted_msg for record in self._deque]


def start_listener():
    """Start the listener thread for multi-process logging."""
    if mp.current_process().name != "MainProcess":
        return

    def _mp_log_listener(log_queue):
        while True:
            record = log_queue.get()
            _logger = logging.getLogger(record.name)
            if _logger.isEnabledFor(record.levelno):
                _logger.handle(record)

    listener_thread = threading.Thread(target=_mp_log_listener, args=(mp_queue,))
    listener_thread.daemon = True
    listener_thread.start()


def setup_logging(default_level=logging.INFO, queue=None):
    """
    Sets up logging using default log config file or log config file set by 'MWCP_LOG_CFG'

    :param default_level: Default log level to set to if config file fails.
    :param queue: Queue used to pass logs to.
    """
    if queue:
        assert mp.current_process().name != "MainProcess"
        logging.root.addHandler(MPChildHandler(queue))
        # If on Windows, allow all records to pass through, this is necessary because Windows
        # subprocesses don't duplicate the global state like posix systems.
        # Therefore, we have to pass all log messages through since effective
        # log level is unknown.
        if "Windows" in platform.platform():
            logging.root.setLevel(logging.DEBUG)
    else:
        # Allow setting log configuration using 'MWCP_LOG_CFG' environment variable.
        log_config = os.getenv("MWCP_LOG_CFG", None)
        if log_config is None:
            log_config = mwcp.config.get("LOG_CONFIG_PATH", None)
        else:
            warnings.warn(
                "Using MWCP_LOG_CFG to set log configuration is deprecated. "
                "Please specify path in the configuration file instead."
            )
        if log_config:
            try:
                with open(log_config, "rt") as f:
                    config = yaml.safe_load(f.read())
                logging.config.dictConfig(config)
            except IOError as e:
                warnings.warn("Unable to set log config file: {} with error: {}".format(log_config, e))
                logging.basicConfig(level=default_level)
        else:
            logging.basicConfig(level=default_level)

        # Startup queue listener if we are in the main process.
        start_listener()
