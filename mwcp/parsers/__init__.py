"""
Interface for registering and accessing parsers.
"""

import collections
import glob
import inspect
import logging
import os
import sys

import mwcp

logger = logging.getLogger(__name__)

# Dictionary containing:
# {
#     parser_name: {source_name: parser_class}
# }
_PARSERS = collections.defaultdict(dict)


def _register_entry_points():
    """
    Registers parsers found in entry_point: "mwcp.parsers"
    :return:
    """
    global _PARSERS
    # if pkg_resources is not available, we are not going to use this feature.
    # resorting on only to parsers founds with parserdir.
    try:
        import pkg_resources
    except ImportError:
        return
    for entry in pkg_resources.iter_entry_points('mwcp.parsers'):
        parser_name = entry.name
        source_name = entry.dist.project_name.lower()   # Sources are case-insenstive.
        klass = entry.load()
        if not issubclass(klass, mwcp.Parser):
            raise ImportError('{!r} is not an subclass of mwcp.Parser'.format(klass))
        _PARSERS[parser_name][source_name] = klass


def register_parser_directory(parser_dir):
    """
    Registers parsers found in parser_dir. This function allows you to register one-off parsers
    that are not part of an installed python package.
    (Files that start with "_" are ignored.)

    :param str parser_dir: An extra directory to look for one-off parsers.
    """
    global _PARSERS

    # In order to import the modules in a cross-compatible way, we are going to have to
    # temporarily extend the path to include the extra_dir
    orig_path = list(sys.path)
    sys.path.insert(0, parser_dir)
    try:
        # Look for .py file parsers in the directory.
        for fullpath in glob.glob(os.path.join(parser_dir, '[!_]*.py')):
            module_name = os.path.basename(fullpath)[:-3]
            # Account for old-style parsers that have a "_malwareconfigparser.py" prefix.
            if module_name.endswith('_malwareconfigparser'):
                parser_name = module_name[:-len('_malwareconfigparser')]
            else:
                parser_name = module_name
            module = __import__(module_name)

            # find descendants of mwcp.Parser in this module.
            for _, klass in inspect.getmembers(module, inspect.isclass):
                if issubclass(klass, mwcp.Parser):
                    _PARSERS[parser_name][parser_dir] = klass
                    break  # Only count the first one we see.
    finally:
        sys.path = orig_path


def iter_parsers(name=None, source=None):
    """
    Iterates all registered parsers.

    :param str name: Filters parser based on a particular name.
    :param str source: Filters parser based on a particular source.
                       (source is either the name of a python package or path to local directory)

    e.g.
    >>> list(iter_parsers())
    [
        ('foo', 'C:\...\parsers', <class 'foo_malwareconfigparser.Foo'>),
        ('foo', 'mwcp-acme', <class 'mwcp-acme.parsers.foo.Foo'>),
        ('bar', 'mwcp-acme', <class 'mwcp-acme.parsers.bar.Bar'>)
    ]
    >>> list(iter_parsers(name='foo'))
    [
        ('foo', 'C:\...\parsers', <class 'foo_malwareconfigparser.Foo'>),
        ('foo', 'mwcp-acme', <class 'mwcp-acme.parsers.foo.Foo'>)
    ]
    >>> list(iter_parsers(source='mwcp-acme'))
    [
        ('foo', 'mwcp-acme', <class 'mwcp_acme.parsers.foo.Foo'>),
        ('bar', 'mwcp-acme', <class 'mwcp_acme.parsers.bar.Bar'>
    ]
    >>> list(iter_parsers(name='foo', source='mwcp-acme'))
    [
        ('foo', 'mwcp-acme', <class 'mwcp_acme.parsers.foo.Foo'>)
    ]

    :yields: tuple containing: (parser_name, source_name, parser_class)
    """
    # Automatically register any parsers found with 'mwcp.parsers' entry_points.
    _register_entry_points()

    # Sources are case-insenstive
    if source:
        source = source.lower()
    parser_dict = {name: _PARSERS.get(name, {})} if name else _PARSERS
    for name, source_dict in parser_dict.items():
        if source:
            source_dict = {source: source_dict.get(source, None)}
        for source_name, klass in source_dict.items():
            if klass:
                yield name, source_name, klass


def get_parser_descriptions():
    """
    Retrieve list of parser descriptions

    Returns list of tuples per parser. Tuple contains parser name, author, and description.
    """
    descriptions = []
    # Since, description and author are instance variables, we are going to have to
    # temporarily initialize them in order to extract their info.
    # TODO: In the future, this information should be static attributes on the class itself.
    reporter = mwcp.Reporter()
    for name, source_name, klass in sorted(iter_parsers()):
        parser = klass(reporter)
        descriptions.append(('{} ({})'.format(name, source_name), parser.author, parser.description))
    return descriptions


