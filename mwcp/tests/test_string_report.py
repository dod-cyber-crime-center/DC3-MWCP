"""
Tests components of string report extension.
"""

from mwcp import metadata


def test_strings(report):
    with report:
        report.add(metadata.DecodedString("hello"))
        report.add(metadata.DecodedString("world", encryption_key=metadata.EncryptionKey(b"\xde\xad\xbe\xef")))
    assert report.strings() == ["hello", "world"]


def test_string_report_generation(report, datadir):
    report._external_strings_report = True
    with report:
        report.add(metadata.DecodedString("hello"))
        report.add(metadata.DecodedString("world", encryption_key=metadata.EncryptionKey(b"\xde\xad\xbe\xef")))
    string_reports = report.get(metadata.File)[:2]
    assert string_reports[0].name.endswith(f"_strings.json")
    assert string_reports[1].name.endswith(f"_strings.txt")
    assert string_reports[0].data.decode("utf8") == (datadir / "strings.json").read_text()
    assert string_reports[1].data.decode("utf8") == (datadir / "strings.txt").read_text()
