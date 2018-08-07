"""This is an example parser used to show the different methods of adding data to the reporter."""
import logging
import os

logger = logging.getLogger(__name__)

from mwcp import Parser


class Foo(Parser):

    def __init__(self, reporter=None):
        Parser.__init__(self,
                        description='example parser that works on any file',
                        author='DC3',
                        reporter=reporter
                        )

    def run(self):
        # retrieve input file
        input_file = self.reporter.input_file

        # standardized metadata
        self.reporter.add_metadata("url", "http://127.0.0.1")

        # demonstrate access to sample
        logger.info("size of inputfile is {} bytes".format(len(input_file.file_data)))

        # other, non-standardized metadata
        # also demonstrate use of pefile object
        if self.reporter.pe:
            self.reporter.add_metadata(
                "other", {"section0": self.reporter.pe.sections[0].Name.rstrip('\x00')})

        # demonstrate file output
        self.reporter.output_file(
            b"hello world", "fooconfigtest.txt", "example output file")

        # demonstrate use of filename()
        logger.info("operating on inputfile {}".format(input_file.file_name))

        # demonstrate use of managed tempdir
        with open(os.path.join(self.reporter.managed_tempdir(), "footmp.txt"), "w") as f:
            f.write("This is a temp file created in a directory that will be managed by the mwcp framework. \
                The directory will initially be empty, so there is no worry about name collisions. \
                The directory is deleted after this module run ends, unless tempcleanup is disabled.")
