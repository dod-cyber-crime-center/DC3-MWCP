"""
A central location to store common windows enumerations.
This module will be imported along with 'from mwcp.utils import construct'
"""

from construct import *

# Visible interface. Add the classes and functions you would like to be available for users of construct
# library here.
__all__ = ['RegHive', 'LanguageIdentifier']


REGHIVES = {
    "HKCR": 0x80000000,
    "HKCU": 0x80000001,
    "HKLM": 0x80000002,
    "HKU":  0x80000003,
    "HKPD": 0x80000004,
    "HKCC": 0x80000005,
    "HKDD": 0x80000006,
}


def RegHive(subcon):
    r"""
    Converts an integer to registry hive enum.

    >>> RegHive(Int32ul).build("HKCU")
    b'\x01\x00\x00\x80'
    >>> RegHive(Int32ul).parse(b'\x01\x00\x00\x80')
    'HKCU'
    """
    return Enum(subcon, **REGHIVES)


# TODO: Extend dictionary to incorporate more languages
LANGUAGEIDENTIFIERS = {
    "English (United States)": 0x409,
    "Korean": 0x412,
    "Chinese (PRC)": 0x804,
}


def LanguageIdentifier(subcon):
    r"""
    Converts an integer to language identifer enum

    >>> LanguageIdentifier(Int32ul).build("English (United States)")
    b'\t\x04\x00\x00'
    >>> LanguageIdentifier(Int32ul).parse(b"\x04\x08\x00\x00")
    'Chinese (PRC)'
    """
    return Enum(subcon, **LANGUAGEIDENTIFIERS)
