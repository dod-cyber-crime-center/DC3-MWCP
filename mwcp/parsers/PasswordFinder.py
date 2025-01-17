import re
import logging
from mwcp import Parser, metadata

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class PasswordFinder(Parser):
    DESCRIPTION = "passwordfinder"
    AUTHOR = "foxtrothotel"

    @classmethod
    def identify(cls, file_object):
        logger.info("PasswordFinder running")
        return True

    def run(self):
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall("(?:password|pass|pwd):(.*)", file_content, re.IGNORECASE)
        logger.info(f"Found {len(matches)}")
        for m in matches:
            self.report.add(metadata.Password(m))
