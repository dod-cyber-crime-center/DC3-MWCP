"""
Utility used for string conversions.
"""

import sys

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

