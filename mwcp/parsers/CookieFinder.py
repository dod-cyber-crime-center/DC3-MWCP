import re
import logging
from mwcp import Parser, metadata
import pdb

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class GenericVOne(Parser):
    DESCRIPTION = "Genericv1 parser of cookie files, matches Chromium based cookie theft (MS/Google)"
    AUTHOR = "fh"

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
    regex = r'([a-zA-Z0-9-\._]+)\x09(?:TRUE|FALSE)\x09\x2F\x09(?:TRUE|FALSE)\x09([123]\d{9})\x09([^\n]+)'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content, re.IGNORECASE)
        for m in matches:
            self.report.add(metadata.Credential(m))
