"""Tests for found bugs/issues."""

import csv
import io
import os
import sys

from click.testing import CliRunner

import mwcp
from mwcp import cli, metadata


def test_missing_residual_file_with_UnableToParse(tmpdir, make_sample_parser):
    """
    Tests bug where residual file isn't reported if a nested parser raises an UnableToParse error on it and
    no other parser picks it up.

    Also tests to ensure misidentified file's description gets reset.
    """
    # language=Python
    CODE = """
from mwcp import FileObject, Parser, UnableToParse


class Carrier(Parser):
    DESCRIPTION = "TestParser Carrier"
    
    @classmethod
    def identify(cls, file_object):
        return file_object.name == "carrier.txt"
        
    def run(self):
        self.logger.info("in Carrier parser")
        self.dispatcher.add(FileObject(b"I'm a downloader", file_name="downloader.txt"))


class Downloader(Parser):
    DESCRIPTION = "TestParser Downloader"
    
    @classmethod
    def identify(cls, file_object):
        return file_object.name == "downloader.txt"
        
    def run(self):
        self.logger.info("in Downloader parser")
        self.dispatcher.add(FileObject(b"I'm a false implant", file_name="implant.txt"))
        self.dispatcher.add(FileObject(b"I'm something else that doesn't get identified.", file_name="other.txt"))


class Implant(Parser):
    DESCRIPTION = "TestParser Implant"
    
    @classmethod
    def identify(cls, file_object):
        return file_object.name == "implant.txt"

    def run(self):
        self.logger.info("in Implant parser")
        raise UnableToParse("Oops, misidentified.")
"""
    # language=Yaml
    CONFIG = """
RootParser:
    description: root parser
    parsers:
        - SubParser
    
SubParser:
    description: sub parser
    parsers:
        - .Carrier
        - .Downloader
        - .Implant
"""
    parser_path, config_file = make_sample_parser(parser_name="SubParser", parser_code=CODE, config_text=CONFIG)
    mwcp.register_parser_directory(str(parser_path.dirname), config_file_path=str(config_file), source_name="ACME")

    input_file = tmpdir / "carrier.txt"
    input_file.write_binary(b"I'm a carrier")
    output_directory = tmpdir / "output"
    output_directory.mkdir()

    report = mwcp.run("RootParser", file_path=str(input_file), output_directory=output_directory)
    print(report.as_text())
    print(report.as_json())

    residual_files = report.get(metadata.File)
    assert len(residual_files) == 3
    assert residual_files[1].name == "implant.txt"
    assert residual_files[1].description == "Unidentified file"
    assert (output_directory / "3e245_implant.txt").exists()


def test_temp_path_with_blank_filename():
    """
    Tests bug #51 where a file name that is all whitespace (or otherwise
    sanitizes to an empty string) produced an invalid temp path that could not
    be written (for example a name of all spaces on Windows). The md5 should be
    used as a fallback instead.
    """
    file_object = mwcp.FileObject(b"some data", file_name="     ")
    with file_object.temp_path() as path:
        assert os.path.basename(path) == file_object.md5
        assert os.path.exists(path)
