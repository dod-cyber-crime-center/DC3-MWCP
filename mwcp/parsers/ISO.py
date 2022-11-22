"""
ISO Image
"""

import isoparser

from mwcp import Parser, FileObject


class ImageFile(Parser):
    DESCRIPTION = "ISO Image File"
    AUTHOR = "DC3"

    MAGIC = b"CD001"
    OFFSETS = [0x8001, 0x8801, 0x9001]

    @classmethod
    def identify(cls, file_object):
        for offset in cls.OFFSETS:
            if file_object.data[offset:offset+len(cls.MAGIC)] == cls.MAGIC:
                return True
        return False

    def recursive_extract(self, record):
        """
        Recursively extract files within each directory of an ISO image.

        :param record: A directory within an iso.ISO object
        """
        for child in record.children:
            if child.is_directory:
                self.recursive_extract(child)
            else:
                self.dispatcher.add(FileObject(child.content, file_name=child.name))

    def run(self):
        """
        Create an iso.ISO object and proceed to extract and output embedded files.

        :return:
        """
        with self.file_object.temp_path() as file_path:
            try:
                with isoparser.parse(file_path) as iso:
                    self.recursive_extract(iso.root)
            except AttributeError as e:
                self.logger.warning(f"Error parsing ISO image file: {e}")
