
import pytest

from mwcp import metadata


@pytest.mark.parametrize("text_format,report_name", [
    ("markdown", "report.md"),
    ("simple", "report.txt"),
    ("html", "report.html"),
])
def test_basic(datadir, report, metadata_items, text_format, report_name):
    """
    Tests each metadata element to ensure they are presented
    nicely in a report.
    """
    with report:
        report.input_file.description = "SuperMalware Implant"
        for item in metadata_items:
            report.add(item)
        report.add_tag("test", "tagging")

    actual = report.as_text(text_format)
    print(actual)
    expected = (datadir / report_name).read_text()
    assert actual == expected


@pytest.mark.parametrize("text_format,report_name", [
    ("markdown", "report_wordwrap.md"),
    ("simple", "report_wordwrap.txt"),
    ("html", "report_wordwrap.html"),
])
def test_wordwrap(datadir, report, text_format, report_name):
    with report:
        report.input_file.description = "SuperMalware Implant"
        large_num = int("123"*50)  # Large number that will require word wrapping.
        report.add(metadata.RSAPublicKey(1234, large_num))
        report.add(metadata.RSAPrivateKey(
            1234, large_num, 1234, large_num, large_num, large_num, large_num, large_num))
        report.add(metadata.UserAgent("This is a really large user agent that will need to be word wrapped." * 16))

    actual = report.as_text(text_format)
    print(actual)
    expected = (datadir / report_name).read_text()
    assert actual == expected


@pytest.mark.parametrize("text_format,report_name", [
    ("markdown", "report_foreign.md"),
    ("simple", "report_foreign.txt"),
    ("html", "report_foreign.html"),
])
def test_foreign_characters(datadir, report, text_format, report_name):
    with report:
        report.input_file.description = "SuperMalware Implant"
        report.add(metadata.Other("JAPAN", "\u30E6\u30FC\u30B6\u30FC\u5225\u30B5\u30A4\u30C8"))
        report.add(metadata.Other("CHINA", "\u7B80\u4F53\u4E2D\u6587"))
        report.add(metadata.Other("KOREA", "\uD06C\uB85C\uC2A4 \uD50C\uB7AB\uD3FC\uC73C\uB85C"))
        report.add(metadata.Other("ISRAEL", "\u05DE\u05D3\u05D5\u05E8\u05D9\u05DD \u05DE\u05D1\u05D5\u05E7\u05E9\u05D9\u05DD"))
        report.add(metadata.Other("EGYPT", "\u0623\u0641\u0636\u0644 \u0627\u0644\u0628\u062D\u0648\u062B"))
        report.add(metadata.Other(
            "RUSSIA",
            "\u0414\u0435\u0441\u044F\u0442\u0443\u044E \u041C\u0435\u0436\u0434\u0443\u043D\u0430"
            "\u0440\u043E\u0434\u043D\u0443\u044E"
        ))
        report.add(metadata.Other("MATH", "\u222E E\u22C5da = Q,  n \u2192 \u221E, \u2211 f(i) = \u220F g(i)"))
        report.add(metadata.Other("FRANCE", "fran\u00E7ais langue \u00E9trang\u00E8re"))
        report.add(metadata.Other("SPAIN", "ma\u00F1ana ol\u00E9"))

    actual = report.as_text(text_format)
    print(actual)
    expected = (datadir / report_name).read_text("utf-8")
    assert actual == expected
