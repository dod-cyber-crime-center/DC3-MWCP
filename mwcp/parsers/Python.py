"""
Parses Python artifacts
"""

import os
from construct import this

from mwcp import Parser, FileObject
from mwcp.utils import construct


class PyInstaller(Parser):
    DESCRIPTION = "PyInstaller"

    TABLE_ENTRY = construct.Struct(
        "entry_size" / construct.Int32ub,
        "offset" / construct.Int32ub,
        "compressed_size" / construct.Int32ub,
        "final_size" / construct.Int32ub,
        "flag" / construct.Flag,
        "type" / construct.Flag,
        "name" / construct.String(this.entry_size - 18),
        "data" / construct.Pointer(
            this.offset,
            construct.IfThenElse(
                this.flag,
                construct.Compressed(construct.Bytes(this.compressed_size), lib="zlib"),
                construct.Bytes(this.compressed_size),
            ),
        ),
    )

    @classmethod
    def identify(cls, file_object):
        """
        Validate the MAGIC data is at the appropriate location
        """
        magic = b'MEI\x0C\x0B\x0A\x0B\x0E'
        if file_object.data[-24:-24 + len(magic)] == magic:
            file_object.knowledge_base["COOKIE_SPEC"] = construct.Struct(
                "magic" / construct.Const(magic),
                "package_size" / construct.Int32ub,
                "toc_offset" / construct.Int32ub,
                "toc_entries" / construct.Int32ub,
                "python_version" / construct.Int32ub,
            )
            return True

        elif file_object.data[-88:-88+len(magic)] == magic:
            file_object.knowledge_base["COOKIE_SPEC"] = construct.Struct(
                "magic" / construct.Const(magic),
                "package_size" / construct.Int32ub,
                "toc_offset" / construct.Int32ub,
                "toc_entries" / construct.Int32ub,
                "python_version" / construct.Int32ub,
                "python_dll" / construct.String(64),
            )
            return True

        return False

    def extract_entry(self, name: str, data: bytes, pyver: int):
        """
        Extracts table of contents entry.
        """
        ext = ".pyc"
        if data[:4] != b'\x63\x00\x00\x00':
            # This indicates the sample is an uncompiled python script
            magic_number = b''
            header = b''
            ext = ".py"
        elif pyver >= 37:  # PEP 552 -- Deterministic pycs
            header = b'\0' * 12  # Bitfield, Timestamp, size
            magic_number = b"\x42\x0d\x0d\x0a"
        elif pyver >= 33:
            header = b'\0' * 8  # (Timestamp + size)
            magic_number = b"\x42\x0d\x0d\x0a"
        else:
            header = b'\0' * 4  # Timestamp
            magic_number = b"\x03\xF3\x0D\x0A"
        data = magic_number + header + data
        self.dispatcher.add(FileObject(data, file_name=name + ext))

    def run(self):
        """
        Extract the cookie information in order to extract and parse the table of contents. Identify the .manifest
        filename in order to obtain the name of the target script to add to the dispatcher.

        """
        cookie_spec = self.file_object.knowledge_base["COOKIE_SPEC"]
        cookie_size = cookie_spec.sizeof()

        cookie = cookie_spec.parse(self.file_object.data[-cookie_size:])
        package = self.file_object.data[-cookie.package_size: -cookie_size]
        package_spec = construct.Struct(
            construct.Padding(cookie.toc_offset),
            "toc" / self.TABLE_ENTRY[:],
        )
        info = package_spec.parse(package)

        # Extract files base on .manifest files.
        target_names = []
        for entry in info.toc:
            if entry.name.endswith(".manifest"):
                target_names.append(os.path.splitext(entry.name)[0].replace(".exe", ''))
        for entry in info.toc:
            if entry.name in target_names:
                self.extract_entry(entry.name, entry.data, cookie.python_version)

        # Extract PYZ archives.
        for entry in info.toc:
            if entry.data.startswith(b"PYZ\x00"):
                self.dispatcher.add(FileObject(entry.data, file_name=entry.name))
