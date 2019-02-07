"""
Utility used for string conversions.
"""


def convert_to_unicode(input_string):
    if isinstance(input_string, bytes):
        return input_string.decode('latin1')
    return input_string

