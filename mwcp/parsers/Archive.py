"""
Parsers for archive type files.
"""

import io
import ntpath
import pathlib
import tarfile
import zipfile

from mwcp import Parser, FileObject


class Zip(Parser):
    DESCRIPTION = "Zip Archive File"

    ZIP_HEADER = b"PK"

    @classmethod
    def identify(cls, file_object):
        """
        Identify as a Zip archive file.
        """
        return file_object.data.startswith(cls.ZIP_HEADER)

    def parse_extracted(self, file_name, file_data):
        self.dispatcher.add(FileObject(file_data, file_name=file_name))

    def run(self):
        """
        Use the zipfile Python library to extract the contents of a Zip archive.
        """
        self.logger.info("Attempting to extract files from Zip archive.")
        try:
            z = zipfile.ZipFile(io.BytesIO(self.file_object.data))
            for obj in z.infolist():
                file_data = z.read(obj)
                file_name = ntpath.basename(obj.filename)
                # see if there is data, before passing to the parse_extracted function
                if not len(file_data):
                    continue
                self.parse_extracted(file_name, file_data)
        except IOError:
            self.logger.exception("Failed to extract Zip archive.")
        except zipfile.BadZipfile:
            self.logger.exception("Invalid zip file")


class Gzip(Parser):
    DESCRIPTION = "Gzip Archive file"

    HEADER = b"\x1F\x8B"

    @classmethod
    def identify(cls, file_object):
        return file_object.data.startswith(cls.HEADER)

    def parse_extracted(self, file_name, file_data):
        self.dispatcher.add(FileObject(file_data, file_name=file_name))

    def run(self):
        with self.file_object.open() as fo:
            with tarfile.open(fileobj=fo, mode="r:gz") as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        data = tar.extractfile(member).read()
                        name = pathlib.Path(member.name).name
                        self.parse_extracted(name, data)
