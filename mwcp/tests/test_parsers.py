import json

import pytest

import mwcp
from mwcp import testing


def _setup(config):
    """
    Registers parsers and loads configuration.
    """
    mwcp.register_entry_points()
    mwcp.config.load()

    # Set any configuration passed in through command line of pytest.
    testcase_dir = config.option.testcase_dir if "testcase_dir" in config.option else None
    malware_repo = config.option.malware_repo if "malware_repo" in config.option else None
    if testcase_dir:
        mwcp.config["TESTCASE_DIR"] = testcase_dir
    if malware_repo:
        mwcp.config["MALWARE_REPO"] = malware_repo


@pytest.fixture(scope="session", autouse=True)
def setup(request):
    _setup(request.config)


def pytest_generate_tests(metafunc):
    """
    Generates the test cases for parametrization of parser tests.
    Add "md5" and "results_path" to your fixtures.
    """
    if not ("md5" in metafunc.fixturenames and "results_path" in metafunc.fixturenames):
        return

    _setup(metafunc.config)

    params = []
    for test_case in mwcp.testing.iter_test_cases():
        params.append(pytest.param(
            test_case.md5, test_case.results_path, id=f"{test_case.name}-{test_case.md5}"
        ))
    metafunc.parametrize("md5,results_path", params)


@pytest.mark.parsers  # Custom mark
def test_parser(md5, results_path):
    input_file_path = testing.get_path_in_malware_repo(md5=md5)

    # Grab expected results.
    with open(results_path, "r") as fo:
        expected_results = json.load(fo)

    # Expected results are allowed to include logs to provide better insight when the
    # test case was first created. However, we don't want to include them in the test since
    # logs can easily change over time.
    expected_results["logs"] = []
    expected_results["errors"] = []

    # Get full parser name from expected results.
    parser_name = expected_results["parser"]

    # NOTE: Reading bytes of input file instead of passing in file path to ensure everything gets run in-memory
    #   and no residual artifacts (like idbs) are created in the malware repo.
    report = mwcp.run(parser_name, data=input_file_path.read_bytes(), include_logs=False)
    actual_results = report.as_json_dict()

    # Remove mwcp version since we don't want to be updating our tests cases every time
    # there is a new version.
    expected_results_version = expected_results.pop("mwcp_version")
    actual_results_version = actual_results.pop("mwcp_version")

    # region - Handle changes in metadata schema so older test cases don't fail.

    # Version 3.3.2 introduced "mode" property in encryption_key. Remove property for older tests.
    if expected_results_version < "3.3.2":
        for item in actual_results["metadata"]:
            if item["type"] == "encryption_key":
                del item["mode"]

    # Version 3.3.3 set "residual_file" and "input_file" types to just "file".
    if expected_results_version < "3.3.3":
        actual_results["input_file"]["type"] = "input_file"
        for item in actual_results["metadata"]:
            if item["type"] == "file":
                item["type"] = "residual_file"

    # Version 3.3.3 also changed the types for legacy interval and uuid to
    # "interval_legacy" and "uuid_legacy" respectively.
    if expected_results_version < "3.3.3":
        for item in actual_results["metadata"]:
            if item["type"].endswith("_legacy"):
                item["type"] = item["type"][:-len("_legacy")]

    # Version 3.3.3 no longer automatically adds tcp into a socket for url,
    # therefore just clear the network_protocol when it's set to tcp for
    # older versions
    if expected_results_version < "3.3.3":
        for item in actual_results["metadata"] + expected_results["metadata"]:
            if item["type"] == "socket" and item["network_protocol"] == "tcp":
                item["network_protocol"] = None

            elif item["type"] == "url" and item["socket"] and item["socket"]["network_protocol"] == "tcp":
                item["socket"]["network_protocol"] = None

        # Deduplicate both lists of metadata dictionary items since changing "tcp" to None will likely
        # create some.
        for item in list(actual_results["metadata"]):
            while actual_results["metadata"].count(item) > 1:
                actual_results["metadata"].remove(item)

        for item in list(expected_results["metadata"]):
            while expected_results["metadata"].count(item) > 1:
                expected_results["metadata"].remove(item)

    # endregion

    # The order the metadata comes in doesn't matter and shouldn't fail the test.
    expected_results["metadata"] = sorted(expected_results["metadata"], key=repr)
    actual_results["metadata"] = sorted(actual_results["metadata"], key=repr)

    # NOTE: When running this in PyCharm, the "<Click to see difference>" may be missing
    # on a failed test if there is a "==" contained within one of the results.
    # This obviously can happen if the results have base64 encoded data.
    # Recommend running the test from command line using pytest-clarity in these cases.
    # Hopefully this eventually gets fixed: youtrack.jetbrains.com/issue/PY-43144
    assert actual_results == expected_results
