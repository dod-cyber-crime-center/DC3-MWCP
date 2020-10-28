"""
Helper methods for setting up multiprocessing workers with logging capabilities
"""

import logging
import multiprocessing as mp
import multiprocessing.pool

logger = logging.getLogger(__name__)

from mwcp import registry
from mwcp.utils import logutil


def initializer(parser_sources, default_source):
    """Initializer function that runs at the beginning of each process creation."""
    registry._sources = parser_sources  # Propagate registered parser information.
    registry._default_source = default_source


class TProcess(mp.Process):
    """
    Slighted modified subclass of :class:`multiprocessing.Process`.

    Use this in place of ``Process`` to enable logging in the spawned process.
    """

    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None):
        kwargs = kwargs or {}
        # NOTE: Forcing group to be None since BaseProcess asserts it to be None.
        super(TProcess, self).__init__(group=None, target=target, name=name, args=args, kwargs=kwargs)
        self.queue = logutil.mp_queue

    def run(self):
        logutil.setup_logging(queue=self.queue)
        logger.debug("Setup logger in {}".format(mp.current_process().name))
        super(TProcess, self).run()


class TPool(mp.pool.Pool):
    """
    Version of :class:`multiprocessing.pool.Pool` that uses :class:`TProcess`.
    """

    Process = TProcess

    def __init__(self, processes=None, maxtasksperchild=None):
        """Overwrite to add initializer."""
        super(TPool, self).__init__(
            processes=processes,
            maxtasksperchild=maxtasksperchild,
            initializer=initializer,
            initargs=(registry._sources, registry._default_source),
        )
