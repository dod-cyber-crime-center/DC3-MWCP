"""
Tests Report class.
"""
import logging
import runpy

import pytest

import mwcp
from mwcp import metadata


@pytest.fixture
def filled_report(report, metadata_items):
    """
    Provides a report filled with metadata examples seen above.
    """
    logger = logging.getLogger("test_report")
    with report:
        for item in metadata_items:
            report.add(item)

        logger.info("Test info log")
        logger.error("Test error log")
        logger.debug("Test debug log")

        report.add_tag("test", "tagging")

    return report


def test_report_dict(datadir, filled_report):
    expected = runpy.run_path(str(datadir / "report.py"))["report"]
    assert filled_report.as_dict() == expected


def test_report_json(datadir, filled_report):
    expected = (datadir / "report.json").read_text().replace("MWCP_VERSION", mwcp.__version__)
    actual = filled_report.as_json()
    print(actual)
    assert actual == expected


def test_split_report(datadir):
    """
    Tests split metadata per file.
    """
    logger = logging.getLogger("test_split_report")
    logging.root.setLevel(logging.INFO)
    input_file = mwcp.FileObject(b"some data", file_path="C:/input_file.bin")
    report = mwcp.Report(input_file, "FooParser", log_level=logging.INFO)
    with report:
        logger.info("Info log in input_file.bin")
        logger.error("Error log in input_file.bin")
        report.add(metadata.Mutex("root_mutex"))

        sub_file = mwcp.FileObject(b"some other data", file_name="sub_file.exe")
        report.add(metadata.File.from_file_object(sub_file))
        report.set_file(sub_file)
        logger.info("Info log in sub_file.exe")
        logger.error("Error log in sub_file.exe")
        report.add(metadata.Mutex("sub_mutex"))

        report.add_tag("test", "tagging")

    assert len(report.get()) == 3

    root_metadata = report.get(source=input_file.md5)
    assert len(root_metadata) == 2
    assert metadata.Mutex("root_mutex") in root_metadata

    sub_metadata = report.get(source=sub_file.md5)
    assert len(sub_metadata) == 1
    assert metadata.Mutex("sub_mutex") in sub_metadata

    assert report.logs == [
        "[+] Info log in input_file.bin",
        "[!] Error log in input_file.bin",
        "[+] Info log in sub_file.exe",
        "[!] Error log in sub_file.exe",
    ]
    assert report.errors == [
        "[!] Error log in input_file.bin",
        "[!] Error log in sub_file.exe",
    ]
    assert report.get_logs(sub_file) == [
        "[+] Info log in sub_file.exe",
        "[!] Error log in sub_file.exe",
    ]
    assert report.get_logs(sub_file, errors_only=True) == [
        "[!] Error log in sub_file.exe",
    ]

    expected = runpy.run_path(str(datadir / "split_report.py"))["split_report"]
    assert report.as_list() == expected


def test_finalized(report):
    """
    Tests that we can't add metadata after it is finalized.
    """
    with report:
        report.add(metadata.URL("example1.com"))
    with pytest.raises(RuntimeError):
        report.add(metadata.URL("example2.com"))


def test_deduplication(report):
    """
    Tests that the same metadata information is dedupped.
    """
    with report:
        report.add(metadata.URL("example.com"))
        report.add(metadata.URL("example.com"))
        report.add(metadata.Socket(address="example.com"))
        report.add(metadata.Socket(address="example.com"))  # equivalent more verbose version.
        report.add(metadata.C2Address(address="example.com"))

        # Set new file source to ensure we dedup across sources (if not split)
        res_file = mwcp.FileObject(b"residual data", file_name="res.exe")
        report.set_file(res_file)
        report.add(metadata.URL("example.com"))
        report.add(metadata.Socket(address="example.com"))

    items = report.get()
    assert items == [
        metadata.URL("example.com"),
        metadata.Network(url=metadata.URL2(url='example.com'), socket=metadata.Socket(address='example.com')),
        metadata.Socket(address="example.com"),
        metadata.C2Address(address="example.com"),
    ]
