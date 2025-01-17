import re
import logging
from mwcp import Parser, metadata

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class GenericVOne(Parser):
    DESCRIPTION = "Genericv1"
    AUTHOR = "fh"

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex=r'URL:(.*?)\nUsername:(.*?)\nPassword(.*?)[$\n]'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content)
        for m in matches:
            self.report.add(metadata.Credential(m))


class GenericVTwo(Parser):
    DESCRIPTION = "Genericv2"
    AUTHOR = "fh"    

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex=r'username:(.*?)\npassword:(.*?)\nwebsite:(.*?)[$\n]'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content)
        for m in matches:
            self.report.add(metadata.Credential(m))


class AzVOne(Parser):
    DESCRIPTION="Parser for Azlt v1"
    AUTHOR = "fh"
    
    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex = r'SOFT:(.*?)\nURL:(.*?)\nUSER:(.*?)\nPASS:(.*?)[\n$]'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content, re.IGNORECASE)
        for m in matches:
            self.report.add(metadata.Credential(m))

