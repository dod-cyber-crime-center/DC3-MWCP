"""
Tests STIX Reports.
"""
import logging

import pytest

import json
from mwcp.stix.report_writer import STIXWriter
import mwcp


class CheatUUID:
    """
    Used to provide a mock that overrides the uuid.uuid4 function with something that is deterministic
    """
    def __init__(self):
        self.counter = 0

    def uuid4(self):
        self.counter += 1
        return "00000000-0000-4006-9000-{:012d}".format(self.counter)


@pytest.fixture
def filled_report(report, metadata_items):
    """
    Provides a report filled with metadata examples seen above.
    """
    logger = logging.getLogger("test_report")

    with report:
        report.input_file.description = "SuperMalware Implant"

        for item in metadata_items:
            report.add(item)

        logger.info("Test info log")
        logger.error("Test error log")
        logger.debug("Test debug log")

        report.add_tag("test", "tagging")

    return report


def test_report_stix(datadir, filled_report, mocker):
    # Instead of creating UUIDv4s we will auto increment them to allow easier compares
    uuid_generator = CheatUUID()
    mocker.patch(
        'uuid.uuid4',
        uuid_generator.uuid4
    )

    # Writer must be initialized with a fixed time so we can easily compare results
    # TODO: Look into using freezegun library.
    writer = STIXWriter(fixed_timestamp="2022-01-01T07:32:00.000Z")
    filled_report.as_stix(writer)
    actual = json.loads(writer.serialize())
    with open(datadir / "report.json", "rt") as input_file:
        expected = json.load(input_file)

    # sometimes the ordering of sco_refs will change so this cleans them up
    for obj in expected["objects"]:
        # always keep the current version of MWCP for the expected result
        if obj["type"] == "malware-analysis":
            obj["version"] = mwcp.__version__

    print(json.dumps(actual, indent=4))
    assert actual == expected
