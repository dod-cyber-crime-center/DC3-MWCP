"""Tests parser registration functionality."""

from __future__ import unicode_literals

import collections
import os

import mwcp


def test_register_parser_directory(monkeypatch, test_parser):
    # Monkey patch parsers registration so previous test runs don't muck with this.
    monkeypatch.setattr('mwcp.parsers._PARSERS', collections.defaultdict(dict))

    # Test registration
    assert not list(mwcp.iter_parsers('test_parser'))
    mwcp.register_parser_directory(os.path.dirname(test_parser))
    parsers = list(mwcp.iter_parsers('test_parser'))
    assert len(parsers) == 1

    # Test it was register properly
    name, source_name, klass = parsers[0]
    assert name == 'test_parser'
    assert source_name == os.path.dirname(test_parser)

    # Test we can also pull by source name.
    parsers = list(mwcp.iter_parsers(source=os.path.dirname(test_parser)))
    assert len(parsers) == 1
    parsers = list(mwcp.iter_parsers(os.path.dirname(test_parser) + ':'))
    assert len(parsers) == 1


def test_parsers_descriptions(monkeypatch, test_parser):
    monkeypatch.setattr('mwcp.parsers._PARSERS', collections.defaultdict(dict))
    mwcp.register_parser_directory(os.path.dirname(test_parser))
    descriptions = list(mwcp.get_parser_descriptions('test_parser'))
    assert len(descriptions) == 1
    assert descriptions[0] == (
        'test_parser',
        os.path.dirname(test_parser),
        'Mr. Tester',
        'A test parser'
    )
