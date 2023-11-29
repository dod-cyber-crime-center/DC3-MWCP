"""
Parsers for test_yara_runner_sibling_dispatch
"""

from mwcp import Parser, FileObject


class Parent(Parser):
    DESCRIPTION = "Parent"

    @classmethod
    def identify(cls, file_object):
        return b"parent" in file_object.data

    def run(self):
        self.dispatcher.add(FileObject(b"sibling 1"))
        self.dispatcher.add(FileObject(b"sibling 2"))


class Sibling1(Parser):
    DESCRIPTION = "Sibling 1"

    @classmethod
    def identify(cls, file_object):
        return b"sibling 1" in file_object.data


class Sibling2(Parser):
    DESCRIPTION = "Sibling 2"

    @classmethod
    def identify(cls, file_object):
        return b"sibling 2" in file_object.data

    def run(self):
        # Testing corner case where we dispatch a file that is a parent of an already processed sibling.
        sibling = self.file_object.siblings[0]
        assert sibling.description == "Sibling 1"  # sanity check
        self.dispatcher.add(FileObject(b"grandchild"), parent=sibling)


class Grandchild(Parser):
    DESCRIPTION = "Grandchild"

    @classmethod
    def identify(cls, file_object):
        return b"grandchild" in file_object.data
