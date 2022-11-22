
from mwcp import Parser, FileObject


class FileA(Parser):
    DESCRIPTION = "File A"

    @classmethod
    def identify(cls, file_object):
        return b"matches file a" in file_object.data

    def run(self):
        self.dispatcher.add(FileObject(b"matches file b"))


class FileB(Parser):
    DESCRIPTION = "File B"

    @classmethod
    def identify(cls, file_object):
        return b"matches file b" in file_object.data
