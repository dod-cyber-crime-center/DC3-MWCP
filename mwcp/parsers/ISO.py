"""
ISO Image
"""

from io import BytesIO

import pycdlib

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

    def walk_handler(self, iso, **kwargs):
        """
        Uses the iso.walk function to walk the ISO image depending on the path
        provided in kwargs.

        :param iso: an open PyCdlib instance
        :param kwargs: Keyword arguments to be passed to the iso.walk function.
        Note that this must include either iso_path, udf_path, joliet_path, or
        rr_path.
        :return:
        """
        for dirname, dirlist, filelist in iso.walk(**kwargs):
            for filename in filelist:
                if dirname == "/":
                    path = dirname + filename
                else:
                    path = dirname + "/" + filename

                filedata = BytesIO()

                if "iso_path" in kwargs:
                    iso.get_file_from_iso_fp(filedata, iso_path=path)
                elif "udf_path" in kwargs:
                    iso.get_file_from_iso_fp(filedata, udf_path=path)
                elif "joliet_path" in kwargs:
                    iso.get_file_from_iso_fp(filedata, joliet_path=path)
                elif "rr_path" in kwargs:
                    iso.get_file_from_iso_fp(filedata, rr_path=path)
                else:
                    return

                self.dispatcher.add(FileObject(file_data=filedata.getvalue(), file_name=filename))

    def run(self):
        """
        Walk the ISO image to extract embedded files.

        :return:
        """
        iso = pycdlib.PyCdlib()
        iso.open_fp(BytesIO(self.file_object.data))

        try:
            self.walk_handler(iso, iso_path="/")

            if iso.has_udf():
                self.logger.info("UDF extension identified")
                self.walk_handler(iso, udf_path="/")

            if iso.has_joliet():
                self.logger.info("Joliet extension identified")
                self.walk_handler(iso, joliet_path="/")

            if iso.has_rock_ridge():
                self.logger.info("Rock Ridge extension identified")
                self.walk_handler(iso, rr_path="/")
        finally:
            iso.close()
