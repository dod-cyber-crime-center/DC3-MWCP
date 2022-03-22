"""Tests parser registration functionality."""

import os

import pytest

import mwcp
from mwcp import registry


def test_register_parser_directory(make_sample_parser):
    registry.clear()

    parser_path, config_path = make_sample_parser()
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
    
    
def test_register_parser_directory2(make_sample_parser):
    registry.clear()

    parser_path, config_path = make_sample_parser()
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


def test_missing_parser_class(make_sample_parser):
    """Tests error handling for a missing parser class."""
    registry.clear()

    parser_path, config_file = make_sample_parser(
        config_text=u'''

Sample:
    description: A test parser
    author: Mr. Tester
    parsers:
        - .Downloader
        - .Implant
        - .NoExist

        '''
    )
    parser_dir = str(parser_path.dirname)

    mwcp.register_parser_directory(parser_dir, config_file_path=str(config_file), source_name='ACME')

    with pytest.raises(RuntimeError) as exec_info:
        list(mwcp.iter_parsers('Sample'))
    assert 'Unable to find Sample.NoExist' in str(exec_info.value)


def test_non_importable_module(make_sample_parser):
    """Tests error handling for non importable module."""
    registry.clear()

    parser_path, config_file = make_sample_parser()
    parser_dir = str(parser_path.dirname)

    # Add garbage so that the module will have an import error
    parser_path.write('\nimport dummy\n', mode='w+')

    mwcp.register_parser_directory(parser_dir, config_file_path=str(config_file), source_name='ACME')

    with pytest.raises(ImportError) as exec_info:
        list(mwcp.iter_parsers('Sample'))
    assert "No module named 'dummy'" in str(exec_info.value)


def test_recursive_error(make_sample_parser):
    """Tests error handling for a recursive parser."""
    registry.clear()

    parser_path, config_file = make_sample_parser(
        config_text=u'''
        
Sample:
    description: A test parser
    author: Mr. Tester
    parsers:
        - .Downloader
        - .Implant
        - Sample2
        
Sample2:
    description: A test parser 2
    author: Mr. Tester
    parsers:
        - Sample.Downloader  # This one should be fine.
        - Sample             # It should complain about this.

        
        '''
    )
    parser_dir = str(parser_path.dirname)

    mwcp.register_parser_directory(parser_dir, config_file_path=str(config_file), source_name='ACME')

    with pytest.raises(RuntimeError) as exec_info:
        list(mwcp.iter_parsers('Sample'))
    assert 'Detected recursive loop: Sample2 -> Sample' in str(exec_info.value)


def test_alias(make_sample_parser):
    """Tests handling of an alias."""
    registry.clear()

    parser_path, config_file = make_sample_parser(
        config_text=u'''

Sample:
    description: A test parser
    author: Mr. Tester
    parsers:
        - .Downloader
        - .Implant

Sample_Alias: Sample

        '''
    )
    parser_dir = str(parser_path.dirname)

    mwcp.register_parser_directory(parser_dir, config_file_path=str(config_file), source_name='ACME')

    parsers = [parser for _, parser in mwcp.iter_parsers()]
    assert [parser.name for parser in parsers] == ["Sample", "Sample_Alias"]
    assert parsers[1].parsers == parsers[0].parsers


def test_external_source(make_sample_parser):
    """Tests importing a parser from an external source."""
    registry.clear()

    parser_path, config_file = make_sample_parser("acme")
    parser_dir = str(parser_path.dirname)

    parser2_path, config2_file = make_sample_parser(
        "acme2",
        parser_name="Sample2",
        parser_code=u'''
from mwcp import Parser

class Decoy(Parser):
    DESCRIPTION = "TestParser2 Decoy"
        ''',
        config_text=r'''
Sample2:
    description: Another test parser
    author: Mrs. Tester
    parsers:
        - .Decoy
        - acme:Sample.Downloader  # imports individual component
        - acme:Sample             # imports parser group
      
Sample:
    description: Another test parser
    author: Mrs. Tester
    parsers:
        - Sample2.Decoy
        - acme:Sample
        
        '''
    )
    parser2_dir = str(parser2_path.dirname)

    # Register 2 parsers.
    mwcp.register_parser_directory(parser_dir, config_file_path=str(config_file), source_name="acme")
    mwcp.register_parser_directory(parser2_dir, config_file_path=str(config2_file), source_name="acme2")

    # Test that Sample2 has Sample and Sample.Downloader in it's sub-parsers.
    parsers = list(mwcp.iter_parsers("Sample2"))
    assert len(parsers) == 1
    Sample2_parser = parsers[0][1]
    assert len(Sample2_parser.parsers) == 3
    assert [(p.name, p.source) for p in Sample2_parser.parsers] == [
        ("Sample2.Decoy", "acme2"),
        ("Sample.Downloader", "acme"),
        ("Sample", "acme"),
    ]

    # Test we don't hit a recursion error when we reference a parser with the same name.
    parsers = list(mwcp.iter_parsers("Sample", source="acme2"))
    assert len(parsers) == 1
    Sample_parser = parsers[0][1]
    assert len(Sample_parser.parsers) == 2
    assert [(p.name, p.source) for p in Sample_parser.parsers] == [
        ("Sample2.Decoy", "acme2"),
        ("Sample", "acme"),
    ]


def test_iter_parsers(make_sample_parser):
    registry.clear()

    parser_path, config_path = make_sample_parser()
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


def test_parsers_descriptions(make_sample_parser):
    registry.clear()

    parser_path, config_path = make_sample_parser()
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