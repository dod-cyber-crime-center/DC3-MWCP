"""
Tests powershell deofuscator
"""

import doctest

from mwcp.utils import poshdeob


def test_doctests():
    """Tests that the doctests work."""
    results = doctest.testmod(poshdeob)
    assert not results.failed
