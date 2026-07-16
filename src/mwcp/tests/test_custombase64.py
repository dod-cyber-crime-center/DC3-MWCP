"""Tests mwcp.utils.custombase64"""

from mwcp.utils import custombase64


def test_base64():
    custom_alphabet = b'EFGHQRSTUVWefghijklmnopIJKLMNOPABCDqrstuvwxyXYZabcdz0123456789+/='
    assert custombase64.b64encode(b'hello world', custom_alphabet) == b'LSoXMS8BO29dMSj='
    assert custombase64.b64decode(b'LSoXMS8BO29dMSj=', custom_alphabet) == b'hello world'


def test_base64_alphabet_without_pad_char():
    # A 64-character alphabet (no explicit padding character) is accepted by
    # _validate_alphabet, so encoding data that needs padding must not raise.
    # MWCP appends '=' as the pad in that case.
    alphabet_64 = b'EFGHQRSTUVWefghijklmnopIJKLMNOPABCDqrstuvwxyXYZabcdz0123456789+/'
    encoded = custombase64.b64encode(b'hello world', alphabet_64)
    assert encoded == b'LSoXMS8BO29dMSj='
    # Round-trips when decoded with the equivalent 65-character alphabet.
    assert custombase64.b64decode(encoded, alphabet_64 + b'=') == b'hello world'


def test_base32():
    custom_alphabet = b'FGHIJQ345RSTUVWXYKLMABCDENOPZ267='
    assert custombase64.b32encode(b'hello world', custom_alphabet) == b'VGLCEPIXJGPC6ZMUUY======'
    assert custombase64.b32decode(b'VGLCEPIXJGPC6ZMUUY======', custom_alphabet) == b'hello world'


def test_base16():
    custom_alphabet = b'78BDE0123F459A6C'
    assert custombase64.b16encode(b'hello world', custom_alphabet) == b'131019191CB7221C2B191E'
    assert custombase64.b16decode(b'131019191CB7221C2B191E', custom_alphabet) == b'hello world'
