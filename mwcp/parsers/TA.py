"""
Wrapper for Techanarchy RATDecoders using techanarchy_bridge
"""

import glob
import os

from mwcp import Parser
from mwcp.resources import techanarchy_bridge, RATDecoders


RAT_DECODERS = [
    os.path.basename(decoder)[:-3]
    for decoder in glob.glob(os.path.dirname(RATDecoders.__file__) + "/[!_]*.py")
]


def run(self):
    name = self.__class__.__name__
    scriptpath = os.path.join(os.path.dirname(RATDecoders.__file__), name + '.py')
    techanarchy_bridge.run_decoder(self, scriptpath)


# Dynamically declare Parser classes.
for name in RAT_DECODERS:
    if name == 'TEMPLATE':
        continue
    klass = type(name, (Parser,), {'DESCRIPTION': name, 'run': run, 'AUTHOR': 'TechAnarchy'})
    klass.__module__ = __name__  # Module originally gets incorrectly set to "abc"
    globals()[name] = klass
