import json

import pytest
from packaging import version

try:
    import dragodis
except ImportError:
    dragodis = None

import mwcp
import mwcp.metadata
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
    for test_case in testing.iter_test_cases():
        params.append(pytest.param(
            test_case.md5, test_case.results_path, id=f"{test_case.name}-{test_case.md5}"
        ))
    metafunc.parametrize("md5,results_path", params)


def _fixup_test_cases(expected_results, actual_results):
    """
    Fixes up test cases to handle differences in schema
    and remove extraneous differences that don't affect the overall parse results.
    """
    # Expected results are allowed to include logs to provide better insight when the
    # test case was first created. However, we don't want to include them in the test since
    # logs can easily change over time.
    expected_results["logs"] = []
    expected_results["errors"] = []

    # Remove mwcp version since we don't want to be updating our tests cases every time
    # there is a new version.
    expected_results_version = version.parse(expected_results.pop("mwcp_version"))
    actual_results_version = version.parse(actual_results.pop("mwcp_version"))

    # Version 3.3.2 introduced "mode" property in encryption_key. Remove property for older tests.
    if expected_results_version < version.parse("3.3.2"):
        for item in actual_results["metadata"]:
            if item["type"] == "encryption_key":
                del item["mode"]

    # Version 3.3.3 set "residual_file" and "input_file" types to just "file".
    if expected_results_version < version.parse("3.3.3"):
        actual_results["input_file"]["type"] = "input_file"
        for item in actual_results["metadata"]:
            if item["type"] == "file":
                item["type"] = "residual_file"

    # Version 3.3.3 also changed the types for legacy interval and uuid to
    # "interval_legacy" and "uuid_legacy" respectively.
    if expected_results_version < version.parse("3.3.3"):
        for item in actual_results["metadata"]:
            if item["type"].endswith("_legacy"):
                item["type"] = item["type"][:-len("_legacy")]

    # Version 3.3.3 no longer automatically adds tcp into a socket for url,
    # therefore just clear the network_protocol when it's set to tcp for
    # older versions
    if expected_results_version < version.parse("3.3.3"):
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

    # Version 3.5.0 adds "value_format" to Other metadata elements
    # and allows for new value types.
    if expected_results_version < version.parse("3.5.0"):
        for item in actual_results["metadata"]:
            if item["type"] == "other":
                del item["value_format"]
                # If we get an integer or boolean, that was meant to be automatically
                # converted to a string.
                if isinstance(item["value"], (int, bool)):
                    item["value"] = str(item["value"])

    # TODO: File recursion to be reintroduced in 3.6.2
    # Version 3.6.0 adds "duplicate" tags to files already parsed and will not include
    # the duplicate residual files that are extracted from such files.
    # To best handle backwards compatibility we are just going to dedup all residual files
    # based on md5.
    # if expected_results_version < "3.6.0":
    #     # Find and remove files with "duplicate" tag.
    #     for item in list(actual_results["metadata"]):
    #         if item["type"] in ("file", "residual_file") and "duplicate" in item["tags"]:
    #             actual_results["metadata"].remove(item)
    #
    #     # Find and remove all duplicate residual files from expected results,
    #     # since they may not exist in new results due to skipped processing.
    #     seen_md5s = set()
    #     for item in list(expected_results["metadata"]):
    #         if item["type"] in ("file", "residual_file"):
    #             if item["md5"] in seen_md5s:
    #                 expected_results["metadata"].remove(item)
    #             else:
    #                 seen_md5s.add(item["md5"])

    # Version 3.6.0 changes schema for Registry.
    # "path" has been removed.
    # "key" has been replaced with a "hive"/"subkey" combo.
    # Update registry entries in expected results to account for new schema.
    if expected_results_version < version.parse("3.6.0"):
        for item in expected_results["metadata"]:
            if item["type"] == "registry":
                reg = mwcp.metadata.Registry2.from_path(item["path"] or "", data=item["data"]).add_tag(*item["tags"])
                item.update(reg.as_json_dict())
                del item["path"]
                del item["key"]

    # Version 3.7.0 changes schema for Path
    # "directory_path", and "name" as been removed in exchange for just a "path" element.
    # Update path entries in expected results to account for new schema.
    if expected_results_version < version.parse("3.7.0"):
        for item in expected_results["metadata"]:
            if item["type"] == "path":
                # Recreate path using backwards compatibility wrapper.
                if item["path"] is not None:
                    path = mwcp.metadata.Path(
                        path=item["path"],
                        is_dir=item["is_dir"],
                        file_system=item["file_system"],
                    )
                else:
                    path = mwcp.metadata.Path(
                        directory_path=item["directory_path"],
                        name=item["name"],
                        is_dir=item["is_dir"],
                        file_system=item["file_system"],
                    )
                path.add_tag(*item["tags"])
                item.update(path.as_json_dict())
                del item["directory_path"]
                del item["name"]

        # "derivation" field was also added. Remove it for older test cases.
        del actual_results["input_file"]["derivation"]
        for item in actual_results["metadata"]:
            if item["type"] in ("file", "residual_file"):
                del item["derivation"]

    # For now, we are going to remove any supplemental generated files created by IDA or Ghidra.
    # These are not deterministic, changing the md5 on each run. Plus the backend disassembler
    # could be different based what the user setup as their default backend disassembler.
    if expected_results_version >= version.parse("3.7.0"):
        # TODO: make this check less hardcoded.
        is_supplemental = lambda item: (
            item["type"] == "file"
            and item["description"] in ("IDA Project File", "Ghidra Project File")
        )
        expected_results["metadata"] = [item for item in expected_results["metadata"] if not is_supplemental(item)]
        actual_results["metadata"] = [item for item in actual_results["metadata"] if not is_supplemental(item)]

    # The order the metadata comes in doesn't matter and shouldn't fail the test.
    # (Using custom repr to ensure dictionary keys are sorted before repr is applied.)
    custom_repr = lambda d: repr(dict(sorted(d.items())) if isinstance(d, dict) else d)
    expected_results["metadata"] = sorted(expected_results["metadata"], key=custom_repr)
    actual_results["metadata"] = sorted(actual_results["metadata"], key=custom_repr)


def _test_parser(pytestconfig, input_file_path, results_path):
    # Grab expected results.
    with open(results_path, "r") as fo:
        expected_results = json.load(fo)

    # Get full parser name from expected results.
    parser_name = expected_results["parser"]
    md5 = expected_results["input_file"]["md5"]

    # Older versions (<=3.9.0) of MWCP don't have the "recursive" flag.
    if "recursive" not in expected_results:
        recursive = expected_results["recursive"] = False
    else:
        recursive = expected_results["recursive"]

    # NOTE: Reading bytes of input file instead of passing in file path to ensure everything gets run in-memory
    #   and no residual artifacts (like idbs) are created in the malware repo.
    report = mwcp.run(parser_name, data=input_file_path.read_bytes(), include_logs=False, recursive=recursive)

    actual_results = report.as_json_dict()

    _fixup_test_cases(expected_results, actual_results)

    # Convert results back to json text to improve comparison report on failure.
    # But avoid doing this if we detect we are in PyCharm. This is because PyCharm's built in comparison
    # tool displays better on the raw dictionary instead of the string.
    if not hasattr(pytestconfig, "_teamcityReporting"):
        actual_results = json.dumps(actual_results, indent=4, sort_keys=True)
        expected_results = json.dumps(expected_results, indent=4, sort_keys=True)

    assert actual_results == expected_results, \
        f"Parser Test Failed \n\tparser = {parser_name}\n\tmd5 = {md5}\n\ttest_case = {results_path}"


@pytest.mark.parsers  # Custom mark
def test_parser(pytestconfig, md5, results_path):
    input_file_path = testing.get_path_in_malware_repo(md5=md5)
    _test_parser(pytestconfig, input_file_path, results_path)
