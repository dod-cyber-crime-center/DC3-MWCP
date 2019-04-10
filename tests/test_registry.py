"""Tests parser registration functionality."""

import collections
import os

import mwcp
from mwcp import registry


def test_register_parser_directory(monkeypatch, Sample_parser):
    # Monkey patch parsers registration so previous test runs don't muck with this.
    monkeypatch.setattr('mwcp.registry._sources', {})

    parser_path, config_path = Sample_parser
    parser_dir = str(parser_path.dirname)

    # Test registration
    assert not list(mwcp.iter_parsers('Sample'))
    mwcp.register_parser_directory(parser_dir, config_file_path=str(config_path))
    parsers = list(mwcp.iter_parsers('Sample'))
    assert len(parsers) == 1

    # Test it was registered properly
    source, parser = parsers[0]
    assert parser.name == 'Sample'
    assert source.name == parser_dir
    assert source.path == parser_dir

    # Test we can also pull by source name.
    parsers = list(mwcp.iter_parsers(source=parser_dir))
    assert len(parsers) == 1
    parsers = list(mwcp.iter_parsers(parser_dir + ':'))
    assert len(parsers) == 1
    
    
def test_register_parser_directory2(monkeypatch, Sample_parser):
    # Monkey patch parsers registration so previous test runs don't muck with this.
    monkeypatch.setattr('mwcp.registry._sources', {})

    parser_path, config_path = Sample_parser
    parser_dir = str(parser_path.dirname)

    # Test registration
    assert not list(mwcp.iter_parsers('Sample'))
    mwcp.register_parser_directory(parser_dir, config_file_path=str(config_path), source_name='ACME')
    parsers = list(mwcp.iter_parsers('Sample'))
    assert len(parsers) == 1

    # Test it was registered properly
    source, parser = parsers[0]
    assert parser.name == 'Sample'
    assert source.name == 'ACME'
    assert source.path == parser_dir

    # Test we can also pull by source name.
    parsers = list(mwcp.iter_parsers(source='ACME'))
    assert len(parsers) == 1
    parsers = list(mwcp.iter_parsers('ACME:'))
    assert len(parsers) == 1


def test_iter_parsers(monkeypatch, Sample_parser):
    monkeypatch.setattr('mwcp.registry._sources', {})
    parser_path, config_path = Sample_parser
    source = os.path.abspath(str(parser_path.dirname))
    mwcp.register_parser_directory(source, config_file_path=str(config_path))

    parsers = list(mwcp.iter_parsers('Sample'))
    assert len(parsers) == 1

    _source, parser = parsers[0]
    assert parser.__class__ == mwcp.Dispatcher
    assert parser.name == 'Sample'
    assert _source.path == source
    assert len(parser.parsers) == 2
    assert parser.DESCRIPTION == 'A test parser'


    parsers = sorted(mwcp.iter_parsers(config_only=False), key=lambda x: x[1].DESCRIPTION)
    assert len(parsers) == 3

    _source, parser = parsers[0]
    assert parser.__class__ == mwcp.Dispatcher
    assert parser.name == 'Sample'
    assert len(parser.parsers) == 2
    downloader_parser, implant_parser = parser.parsers
    assert parser.DESCRIPTION == 'A test parser'
    assert downloader_parser.DESCRIPTION == 'TestParser Downloader'
    assert implant_parser.DESCRIPTION == 'TestParser Implant'

    assert parsers[1][1] == downloader_parser
    assert parsers[2][1] == implant_parser


def test_parsers_descriptions(monkeypatch, Sample_parser):
    monkeypatch.setattr('mwcp.registry._sources', {})
    parser_path, config_path = Sample_parser
    source = os.path.abspath(str(parser_path.dirname))
    mwcp.register_parser_directory(source, config_file_path=str(config_path))

    # Test bogus
    descriptions = list(mwcp.get_parser_descriptions('bogus'))
    assert descriptions == []

    # Test config only
    descriptions = list(mwcp.get_parser_descriptions())
    assert descriptions == [
        ('Sample', source, 'Mr. Tester', 'A test parser')
    ]
    descriptions = list(mwcp.get_parser_descriptions('Sample'))
    assert descriptions == [
        ('Sample', source, 'Mr. Tester', 'A test parser')
    ]
    descriptions = list(mwcp.get_parser_descriptions(source=source))
    assert descriptions == [
        ('Sample', source, 'Mr. Tester', 'A test parser')
    ]

    # Test all non-config only
    descriptions = list(mwcp.get_parser_descriptions('Sample', config_only=False))
    assert descriptions == [
        ('Sample', source, 'Mr. Tester', 'A test parser')
    ]

    descriptions = list(mwcp.get_parser_descriptions(config_only=False))
    assert descriptions == [
        ('Sample', source, 'Mr. Tester', 'A test parser'),
        ('Sample.Downloader', source, '', 'TestParser Downloader'),
        ('Sample.Implant', source, '', 'TestParser Implant'),
    ]
    descriptions = list(mwcp.get_parser_descriptions('Sample.Downloader', config_only=False))
    assert descriptions == [
        ('Sample.Downloader', source, '', 'TestParser Downloader')
    ]

    descriptions = list(mwcp.get_parser_descriptions(source=source, config_only=False))
    assert descriptions == [
        ('Sample', source, 'Mr. Tester', 'A test parser'),
        ('Sample.Downloader', source, '', 'TestParser Downloader'),
        ('Sample.Implant', source, '', 'TestParser Implant'),
    ]

    # Test using ":" syntax
    descriptions = list(mwcp.get_parser_descriptions(':Sample', config_only=False))
    assert descriptions == [
        ('Sample', source, 'Mr. Tester', 'A test parser')
    ]
    descriptions = list(mwcp.get_parser_descriptions(source + ':', config_only=False))
    assert descriptions == [
        ('Sample', source, 'Mr. Tester', 'A test parser'),
        ('Sample.Downloader', source, '', 'TestParser Downloader'),
        ('Sample.Implant', source, '', 'TestParser Implant'),
    ]