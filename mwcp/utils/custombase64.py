"""
Custom Base64 related utility
"""

import base64
import logging
import sys


PY3 = sys.version_info.major == 3

if PY3:
    maketrans = bytes.maketrans
else:
    from string import maketrans


logger = logging.getLogger(__name__)


# Standard alphabet base on size.
_STD_ALPHA = {
    16: b'0123456789ABCDEF',
    32: b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=',
    64: b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
}


def _validate_alphabet(alphabet, type):
    """
    validate the custom alphabet
        - 64 or 65 characters
        - mappings are unique
    """
    if len(alphabet) not in (type, type+1):
        raise ValueError('invalid alphabet provided')

    if len(alphabet) != len(set(alphabet)):
        raise ValueError('mapping must be unique')

    return


def _adjust_pad(alphabet, data, decode):
    logger.warning('The padding character has not been specified in the custom alphabet')

    if not (len(data) * 8) % 6:
        logger.info('The data does not require the padding character.  continuing')
        return alphabet

    if decode:
        for char in data:
            if char not in alphabet:
                logger.info(
                    'The character "{}" does not appear in the alphabet, '
                    'but was found in the encoded data.  it will be used as the padding char'.format(char))
                return alphabet + bytes([char]) if isinstance(char, int) else char  # support for python 2 or 3
        raise ValueError('please provide a padding character to the custom alphabet')
    else:
        if b'=' not in alphabet:
            return alphabet + b'='
        else:
            raise ValueError('ERROR: please provide a padding character to the custom alphabet')


def _code(data, custom_alpha, size, decode, code_func):
    if isinstance(custom_alpha, str if PY3 else unicode):
        custom_alpha = custom_alpha.encode()
    if isinstance(data, str if PY3 else unicode):
        data = data.encode()
    _validate_alphabet(custom_alpha, size)
    if size != 16 and len(custom_alpha) == size:
        _adjust_pad(custom_alpha, data, decode)
    std_alpha = _STD_ALPHA[size]

    if decode:
        table = maketrans(custom_alpha, std_alpha)
        data = data.translate(table)
        return code_func(data)
    else:
        table = maketrans(std_alpha, custom_alpha)
        data = code_func(data)
        return data.translate(table)


def b64encode(data, alphabet):
    return _code(data, alphabet, 64, False, base64.b64encode)


def b64decode(data, alphabet):
    data += alphabet[-1] * ((-len(data)) % 4)           # Pad the data, if necessary
    return _code(data, alphabet, 64, True, base64.b64decode)


def b32encode(data, alphabet):
    return _code(data, alphabet, 32, False, base64.b32encode)


def b32decode(data, alphabet):
    return _code(data, alphabet, 32, True, base64.b32decode)


def b16encode(data, alphabet):
    return _code(data, alphabet, 16, False, base64.b16encode)


def b16decode(data, alphabet):
    return _code(data, alphabet, 16, True, base64.b16decode)
