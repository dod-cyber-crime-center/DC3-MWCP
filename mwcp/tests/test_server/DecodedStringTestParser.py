"""
Sample parser that reports decoded strings.
"""

from mwcp import metadata, Parser


class Implant(Parser):
    DESCRIPTION = "Sample Implant"

    @classmethod
    def identify(cls, file_object):
        return True

    def run(self):
        self.report.add(metadata.DecodedString("string A"))
        self.report.add(metadata.DecodedString("string B", encryption_key=metadata.EncryptionKey(b"\xde\xad\xbe\xef", "xor")))
