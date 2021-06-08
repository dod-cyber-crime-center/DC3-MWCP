"""
Utilities for managing parser tests (and the malware repository)
"""

import collections
import hashlib
import json
import logging
import pathlib
import re
import shutil
from typing import Iterable, Union, List

import pkg_resources

import mwcp
from mwcp import registry

logger = logging.getLogger(__name__)


TestCase = collections.namedtuple("TestCase", ["name", "md5", "results_path"])


def get_path_in_malware_repo(file_path: Union[str, pathlib.Path] = None, md5: str = None) -> pathlib.Path:
    """
    Gets file path for a file in the malware_repo based on the md5 of the given file_path.
    """
    # TODO: Load config here?
    malware_repo = mwcp.config.get("MALWARE_REPO")
    if not malware_repo:
        raise ValueError("Malware Repository not set.")
    if file_path:
        with open(file_path, "rb") as fo:
            md5 = hashlib.md5(fo.read()).hexdigest()
    if not md5:
        raise ValueError(f"Missing file_path or md5 parameter.")
    return pathlib.Path(malware_repo, md5[:4], md5)


def add_to_malware_repo(file_path: Union[str, pathlib.Path]) -> pathlib.Path:
    """
    Adds the given file path to the malware repo.
    Returns resulting destination path.
    """
    file_path = pathlib.Path(file_path)
    dest_file_path = get_path_in_malware_repo(file_path)

    if dest_file_path.exists():
        logger.info(f"File already exists in malware repo: {dest_file_path}")
        return dest_file_path

    dest_file_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"Copying {file_path} to {dest_file_path}")
    shutil.copy(file_path, dest_file_path)
    return dest_file_path


def _get_testcase_dir_from_source(source: registry.Source) -> pathlib.Path:
    """
    Returns the testcase directory for the given source.
    """
    if source.is_pkg:
        # Dynamically pull based on top level module.
        return pathlib.Path(pkg_resources.resource_filename(source.path, "tests"))

    # If source is a directory, assume there is a "tests" folder within it.
    return pathlib.Path(source.path, "tests")


def get_testcase_dir(source: registry.Source) -> pathlib.Path:
    """
    Returns the testcase directory for the given parser name or source.
    """
    # Use hardcoded testcase directory if set.
    testcase_dir = mwcp.config.get("TESTCASE_DIR")
    if testcase_dir:
        return pathlib.Path(testcase_dir, source.name)

    return _get_testcase_dir_from_source(source)


def iter_test_cases(source: registry.Source = None) -> Iterable[TestCase]:
    """
    Iterates the test cases discovered from a specific or all registered sources.

    :param source: Optional source to obtain test cases for.
    :yields: tests cases
    """
    testcase_dirs = []
    # First see if user provided a global testcase directory that overrides all sources.
    # Test case directories are organized into sub directories based on source name.
    testcase_dir = mwcp.config.get("TESTCASE_DIR")
    if testcase_dir:
        testcase_dir = pathlib.Path(testcase_dir)
        for source_dir in testcase_dir.iterdir():
            if source_dir.is_dir() and registry.is_source(source_dir.name):
                testcase_dirs.append((source_dir.name, source_dir))

    # Otherwise we need to pull test case directories based on location of source.
    else:
        sources = [source] if source else registry.get_sources()
        for source in sources:
            testcase_dirs.append((source.name, _get_testcase_dir_from_source(source)))

    for source_name, testcase_dir in testcase_dirs:
        if not testcase_dir.exists():
            logger.warning(f"Missing test case directory: {testcase_dir}")
            continue
        for file_path in testcase_dir.glob("[!_]*/[!_]*.json"):
            parser_name = file_path.parent.name
            md5 = file_path.stem
            if not re.match("[a-f0-9]{32}", md5):
                continue
            yield TestCase(f"{source_name}:{parser_name}", md5, file_path)


def add_tests(file_path: Union[str, pathlib.Path], parsers: List[str] = None, force=False, update=True) -> bool:
    """
    Adds a test case for the given parser and md5 for malware sample.

    :param file_path: Input file to run given parsers on to create tests.
    :param parsers: List of parser names to create test cases for.
        (Or None to use all registered parsers)
    :param force: Whether to force adding the test case even if errors are encountered
    :param update: Whether to allow updating the test case if a test for this file already exists.

    :returns: Whether we were able successfully add all test cases.
    """
    file_path = pathlib.Path(file_path)
    file_data = file_path.read_bytes()
    md5 = hashlib.md5(file_data).hexdigest()

    add_to_malware_repo(file_path)

    # Run on all parsers if not provided.
    if not parsers:
        parsers = [None]

    success = True
    for parser_name in parsers:
        for source, parser in mwcp.iter_parsers(parser_name):
            testcase_dir = get_testcase_dir(source)
            results_path = testcase_dir / parser.name / f"{md5}.json"
            results_path.parent.mkdir(exist_ok=True)
            full_parser_name = f"{source.name}:{parser.name}"

            if results_path.exists() and not update:
                logger.warning(
                    f"Test case for {file_path} already exists in {results_path}"
                )
                continue

            report = mwcp.run(full_parser_name, data=file_data, log_level=logging.INFO)

            if report.errors and not force:
                logger.warning(
                    f"Results for {file_path} with parser {full_parser_name} "
                    f"has the following errors, not adding:"
                )
                logger.warning("\n".join(report.errors))
                success = False
                continue

            logger.info(f"Adding results for {file_path} in {results_path}")
            results_path.write_text(report.as_json())

    return success


def update_tests(parsers: List[str] = None, force: bool = False) -> bool:
    """
    Updates the test case for the given parser.

    :param parsers: List of parser names to update test cases for.
        (Or None to use all registered parsers)
    :param force: Whether to force adding the test case even if errors are encountered

    :returns: Whether we were able successfully update all test cases.
    """
    if not parsers:
        test_cases = iter_test_cases()
    else:
        def _test_cases():
            cache = set()
            for parser_name in parsers:
                for source, parser in mwcp.iter_parsers(parser_name):
                    if source not in cache:
                        cache.add(source)
                        for test_case in iter_test_cases(source):
                            if parser_name in test_case.name:
                                yield test_case
        test_cases = _test_cases()

    success = True
    for test_case in test_cases:
        results_path = test_case.results_path
        with open(results_path, "r") as fo:
            old_results = json.load(fo)
        parser_name = old_results["parser"]

        file_path = get_path_in_malware_repo(md5=test_case.md5)
        if not file_path.exists():
            logger.warning(f"Unable to update {test_case.name}. Missing {file_path}")
            success = False
            continue

        report = mwcp.run(parser_name, data=file_path.read_bytes(), log_level=logging.INFO)
        if report.errors and not force:
            logger.warning(f"Results for {test_case.name} has the following errors, not updating:")
            logger.warning("\n".join(report.errors))
            success = False
            continue

        logger.info(f"Updating results for {file_path} in {results_path}")
        results_path.write_text(report.as_json())

    return success


def remove_tests(file_path: Union[str, pathlib.Path], parsers: List[str] = None):
    """
    Removes the test case for the given parser and md5 of malware sample.

    :param file_path: Input file to run given parsers on to create tests.
    :param parsers: List of parser names to remove test cases for.
        (Or None to use all registered parsers)
    """
    file_path = pathlib.Path(file_path)
    file_data = file_path.read_bytes()
    md5 = hashlib.md5(file_data).hexdigest()

    if not parsers:
        parsers = [None]

    for parser_name in parsers:
        for source, parser in mwcp.iter_parsers(parser_name):
            testcase_dir = get_testcase_dir(source)
            results_path = testcase_dir / parser.name / f"{md5}.json"

            if results_path.exists():
                logger.info(f"Removing test case: {results_path}")
                results_path.unlink()
