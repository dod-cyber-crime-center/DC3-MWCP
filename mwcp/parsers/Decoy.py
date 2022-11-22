"""
This module contains parsers for common Decoy documents.
"""

from mwcp import Parser


class Base(Parser):
    # Must be implemented in child class
    HEADER = None
    EXT = None

    @classmethod
    def identify(cls, file_object):
        """
        Validate the file starts with the file header
        """
        if not cls.HEADER:
            raise NotImplementedError("[*] HEADER was not set.")
        return file_object.data.startswith(cls.HEADER)

    def run(self):
        # Update file extension if unknown or generic .bin
        if self.EXT and self.file_object.ext in ("", ".bin"):
            self.file_object.ext = self.EXT


class DOC(Base):
    DESCRIPTION = "Decoy Document (.doc)"

    HEADER = b"\xd0\xcf\x11\xe0"
    EXT = ".doc"


class PDF(Base):
    DESCRIPTION = "Decoy Document (.pdf)"

    HEADER = b"%PDF-"
    EXT = ".pdf"


class RTF(Base):
    DESCRIPTION = "Decoy Document (.rtf)"

    HEADER = b"{\\rt"
    EXT = ".rtf"


class JPG(Base):
    DESCRIPTION = "Decoy (.jpg)"

    HEADER = b"\xff\xd8\xff\xe0"
    EXT = ".jpg"


class XMLDocument(Base):
    DESCRIPTION = "Decoy XML Document"

    HEADER = b"PK\x03\x04"
    # Must be implemented by child class
    RELS_PATH = None

    @classmethod
    def identify(cls, file_object):
        if not super().identify(file_object):
            return False
        if cls.RELS_PATH:
            return cls.RELS_PATH in file_object.data
        else:
            return True


class DOCX(XMLDocument):
    DESCRIPTION = "Decoy Document (.docx)"

    EXT = ".docx"
    RELS_PATH = b"word/_rels"


class XLSX(XMLDocument):
    DESCRIPTION = "Decoy Document (.xlsx)"

    EXT = ".xlsx"
    RELS_PATH = b"xl/_rels"


class PPTX(XMLDocument):
    DESCRIPTION = "Decoy Document (.pptx)"

    EXT = ".pptx"
    RELS_PATH = b"ppt/_rels"
