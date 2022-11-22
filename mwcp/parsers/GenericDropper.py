"""
This module contains parsers for common Dropper types containing embedded file(s) in plaintext
"""

from mwcp import FileObject, Parser
from mwcp.utils import pefileutils


class Overlay(Parser):
    DESCRIPTION = "Dropper (Overlay)"

    @classmethod
    def identify(cls, file_object):
        """
        Validate input file is a PE and there is a pefile.PE object starting at the overlay.
        """
        if not file_object.pe:
            return False
        overlay = file_object.pe.get_overlay()
        return overlay and pefileutils.obtain_pe(overlay)

    def run(self):
        """
        Extract PE file from overlay and add to dispatcher
        """
        overlay = self.file_object.pe.get_overlay()
        self.dispatcher.add(FileObject(overlay))


class RSRC(Parser):
    DESCRIPTION = "Dropper (RSRC)"

    @classmethod
    def identify(cls, file_object):
        """
        Validate a PE file is in the resources in plaintext
        """
        return (
            file_object.pe
            and any(pefileutils.obtain_pe(rsrc.data) for rsrc in file_object.resources)
        )

    def run(self):
        """
        Extract embedded PE files from resources

        :return:
        """
        for rsrc in self.file_object.resources:
            file = FileObject(rsrc.data, def_stub=rsrc.fname_stub)
            if file.pe:
                self.logger.info(f"PE file identified in resource {rsrc.rsrc_entry}")
                self.dispatcher.add(file)
