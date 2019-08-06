"""
Utility used for string conversions.
"""

import string
import sys
import unicodedata

if sys.version_info < (3,):
    ustr = unicode
else:
    ustr = str


def convert_to_unicode(input_value):
    if isinstance(input_value, ustr):
        return input_value
    elif isinstance(input_value, bytes):
        return ustr(input_value, encoding='latin1', errors='replace')
    else:
        return convert_to_unicode(str(input_value))


VALID_FILENAME_CHARS = '-_.() {}{}'.format(string.ascii_letters, string.digits)


def sanitize_filename(filename):
    """Convert given filename to sanitized version."""
    filename = convert_to_unicode(filename)
    filename = unicodedata.normalize('NFKD', filename)  # convert accented characters
    return convert_to_unicode(
        ''.join(c for c in filename.encode('ascii', 'ignore') if c in VALID_FILENAME_CHARS))
