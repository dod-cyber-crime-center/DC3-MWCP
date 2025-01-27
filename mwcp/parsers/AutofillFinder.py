import re
import logging
from mwcp import Parser, metadata
import pdb

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class GenericVOne(Parser):
    DESCRIPTION = "Genericv1 parser of Autofill data files"
    AUTHOR = "fh"

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex = r'([a-z0-9_\[\]\-\.]+)\:\s*([^\n]+)\n'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content, re.IGNORECASE)
        for m in matches:
            self.report.add(metadata.Other('Autofill_data',m))
