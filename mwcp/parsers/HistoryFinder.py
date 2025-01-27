import re
import logging
from mwcp import Parser, metadata
import pdb

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class GenericVOne(Parser):
    DESCRIPTION = "Genericv1 parser of History data files"
    AUTHOR = "fh"

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex = r'url\:\s*([^\n]+)\ntitle\:\s*[^\n]+\nvisit\scount\:\s*([^\n]+)\n\-+\n'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content, re.IGNORECASE)
        for m in matches:
            self.report.add(metadata.Other('browser_visit_history',m))
