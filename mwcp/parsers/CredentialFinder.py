import re
import logging
from mwcp import Parser, metadata
import pdb

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class GenericVOne(Parser):
    DESCRIPTION = "Genericv1"
    AUTHOR = "fh"

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex=r'url\s*[^\s]\s*([^\n]*)\n\s*username\s*[^\s]\s*([^\n]*)\n\s*password\s*[^\s]\s*([^\n]*)[\n$\s]'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content, re.IGNORECASE)
        for m in matches:
            self.report.add(metadata.Credential(m))


class GenericVTwo(Parser):
    DESCRIPTION = "Genericv2"
    AUTHOR = "fh"    

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex=r'username:\s*(.*?)\npassword:\s*(.*?)\nwebsite:\s*(.*?)[$\n]'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content)
        for m in matches:
            self.report.add(metadata.Credential(m))

class GenericVThree(Parser):
    DESCRIPTION = "Genericv3"
    AUTHOR = "fh"    

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex = r'\s*url\s*:\s*([^\n]*)\n\s*login\s*:\s*([^\n]*)\n\s*password\s*:\s*([^\n]*)[\n$]'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content,re.IGNORECASE)
        for m in matches:
            self.report.add(metadata.Credential(m))

class AzVOne(Parser):
    DESCRIPTION="Parser for Azlt v1"
    AUTHOR = "fh"
    
    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex = r'SOFT:\s*(.*?)\nURL:\s*(.*?)\nUSER:\s*(.*?)\nPASS:\s*(.*?)[\n$]'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content, re.IGNORECASE)
        for m in matches:
            self.report.add(metadata.Credential(m))


class AzVTwo(Parser):
    DESCRIPTION="Parser for Azlt v2"
    AUTHOR = "fh"
    
    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex = r'Browser:\s*(.*?)\nUrl:\s*(.*?)\nLogin:\s*(.*?)\nPass:\s*(.*?)[\n$]'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content, re.IGNORECASE)
        for m in matches:
            self.report.add(metadata.Credential(m))

class AzVThree(Parser):
    DESCRIPTION="Parser for Azlt v3"
    AUTHOR = "fh"
    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        regex = r'Soft:\s*([^\n]*)\nHost:\s*([^\n]*)\nLogin:\s*([^\n]*)\nPassword:\s*([^\n]*)\n'
        logger.info(f"{self.DESCRIPTION} by {self.AUTHOR}")
        file_content = self.file_object.data.decode(errors="backslashreplace")
        matches = re.findall(regex, file_content, re.IGNORECASE)
        for m in matches:
            self.report.add(metadata.Credential(m))
