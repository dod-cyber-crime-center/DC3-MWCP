"""Tests for found bugs/issues."""

import csv
import io
import sys

from click.testing import CliRunner

import mwcp
from mwcp import cli, metadata


def test_csv_row_bug_legacy(tmp_path, test_dir):
    """
    Tests bug where first row is formatted different from other rows.
    Occurs when outputting csv and input file is a directory.
    """
    runner = CliRunner(mix_stderr=False)

    with runner.isolated_filesystem(tmp_path):

        ret = runner.invoke(cli.main, [
            "parse", "foo",
            "--format", "csv", str(test_dir / "*"),
            "--no-output-files",
            "--legacy",
        ])
        print(ret.stdout)
        print(ret.stderr, file=sys.stderr)
        assert ret.exit_code == 0

        reader = csv.reader(io.StringIO(ret.stdout))
        rows = list(reader)
        assert len(rows) == len(test_dir.listdir()) + 1
        assert rows[0] == ["scan_date", "inputfilename", "outputfile.name",
                           "outputfile.description", "outputfile.md5", "address", "debug", "url"]
        for i, row in enumerate(rows[1:]):
            assert row[0] and row[1]
            # Test entries except the timestamp and full file path.
            # NOTE: order is not guaranteed due to glob pattern, therefore we are testing all but
            #   the debug message which contains the input filename.
            assert row[2] == "fooconfigtest.txt"
            assert row[3] == "example output file"
            assert row[4] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
            # TODO: Figure out how to guarantee file order.
            # assert row[2:] == [
            #     "fooconfigtest.txt",
            #     "example output file",
            #     "5eb63bbbe01eeed093cb22bb8f5acdc3",
            #     "127.0.0.1",
            #     ("[+] File test_{0}.txt identified as Foo.\n"
            #     "[+] size of inputfile is 23 bytes\n"
            #     "[+] operating on inputfile test_{0}.txt").format(i),
            #     "http://127.0.0.1",
            # ]

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
    assert residual_files[1].file_path == str(output_directory / "3e245_implant.txt")
