"""
Utility used for string conversions.
"""

import string
import unicodedata


def convert_to_unicode(input_value):
    if isinstance(input_value, str):
        return input_value
    elif isinstance(input_value, bytes):
        return str(input_value, encoding="latin1", errors="replace")
    else:
        return convert_to_unicode(str(input_value))


VALID_FILENAME_CHARS = "-_.() {}{}".format(string.ascii_letters, string.digits).encode("ascii")


def sanitize_filename(filename):
    """Convert given filename to sanitized version."""
    filename = convert_to_unicode(filename)
    filename = unicodedata.normalize("NFKD", filename)  # convert accented characters

    return convert_to_unicode(bytes(c for c in filename.encode("ascii", "ignore") if c in VALID_FILENAME_CHARS))
