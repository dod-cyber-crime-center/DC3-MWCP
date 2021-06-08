# TODO

import mwcp


def test_running_parser_class():
    from mwcp import Parser

    class TestParser(Parser):
        ...

    report = mwcp.run(TestParser, data=b"test")
    assert report
    assert report.parser == "TestParser"
