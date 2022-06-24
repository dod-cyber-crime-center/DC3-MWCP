"""This is an example parser used to show the different methods of adding data to the reporter."""
import logging
import os

from mwcp import Parser, FileObject, metadata

logger = logging.getLogger(__name__)


class Foo(Parser):
    DESCRIPTION = "Foo"

    @classmethod
    def identify(cls, file_object):
        # identifies if the parser can parse the given file.
        # checking filename to avoid infinite loop.
        return file_object.name != "fooconfigtest.txt"

    def run(self):
        # retrieve input file
        input_file = self.file_object

        # standardized metadata
        self.report.add(metadata.URL("http://127.0.0.1"))

        # demonstrate access to sample
        logger.info(f"size of inputfile is {len(input_file.data)} bytes")

        # other, non-standardized metadata
        # also demonstrate use of pefile object
        if input_file.pe:
            self.report.add(metadata.Other(
                "section0", input_file.pe.sections[0].Name.rstrip(b"\x00")
            ))

        # Dispatch residual files to also be processed.
        self.dispatcher.add(FileObject(
            b"hello world",
            file_name="fooconfigtest.txt",
            description="example output file",
            derivation="extracted and decompressed",
        ))
        #  Alternatively we can manually report a residual file without being processed.
        if False:
            self.report.add(metadata.File(
                "fooconfigtest.txt", description="example output file", data=b"hello world"
            ))

        # demonstrate use of filename()
        logger.info(f"operating on inputfile {input_file.name}")
