"""This is an example parser used to show the different methods of adding data to the reporter."""
import logging
import os

from mwcp import Parser

logger = logging.getLogger(__name__)


class Foo(Parser):
    DESCRIPTION = "Foo"

    @classmethod
    def identify(cls, file_object):
        # identifies if the parser can parse the given file.
        return True

    def run(self):
        # retrieve input file
        input_file = self.file_object

        # standardized metadata
        self.reporter.add_metadata("url", u"http://127.0.0.1")

        # demonstrate access to sample
        logger.info("size of inputfile is {} bytes".format(len(input_file.file_data)))

        # other, non-standardized metadata
        # also demonstrate use of pefile object
        if input_file.pe:
            self.reporter.add_metadata("other", {"section0": input_file.pe.sections[0].Name.rstrip(b"\x00")})

        # demonstrate file output
        self.reporter.output_file(b"hello world", "fooconfigtest.txt", "example output file")

        # demonstrate use of filename()
        logger.info("operating on inputfile {}".format(input_file.file_name))

        # demonstrate use of managed tempdir
        with open(os.path.join(self.reporter.managed_tempdir, "footmp.txt"), "w") as f:
            f.write(
                "This is a temp file created in a directory that will be managed by the mwcp framework. \
                The directory will initially be empty, so there is no worry about name collisions. \
                The directory is deleted after this module run ends, unless tempcleanup is disabled."
            )
