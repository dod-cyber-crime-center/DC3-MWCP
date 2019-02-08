"""Tests mwcp.utils.custombase64"""

from mwcp.utils import custombase64


def test_base64():
    custom_alphabet = b'EFGHQRSTUVWefghijklmnopIJKLMNOPABCDqrstuvwxyXYZabcdz0123456789+/='
    assert custombase64.b64encode(b'hello world', custom_alphabet) == b'LSoXMS8BO29dMSj='
    assert custombase64.b64decode(b'LSoXMS8BO29dMSj=', custom_alphabet) == b'hello world'


def test_base32():
    custom_alphabet = b'FGHIJQ345RSTUVWXYKLMABCDENOPZ267='
    assert custombase64.b32encode(b'hello world', custom_alphabet) == b'VGLCEPIXJGPC6ZMUUY======'
    assert custombase64.b32decode(b'VGLCEPIXJGPC6ZMUUY======', custom_alphabet) == b'hello world'


def test_base16():
    custom_alphabet = b'78BDE0123F459A6C'
    assert custombase64.b16encode(b'hello world', custom_alphabet) == b'131019191CB7221C2B191E'
    assert custombase64.b16decode(b'131019191CB7221C2B191E', custom_alphabet) == b'hello world'
