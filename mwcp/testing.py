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
from dataclasses import dataclass
from typing import Iterable, Union, List

import pkg_resources

import mwcp
from mwcp import registry

logger = logging.getLogger(__name__)


@dataclass
class TestCase:
    name: str
    md5: str
    results_path: pathlib.Path

    def update(self, force=False) -> bool:
        """
        Updates test case based on currently generated results.

        :param force: Whether to force adding the test case even if errors are encountered
        :returns: Whether update was successful.
        """
        results_path = self.results_path
        with open(results_path, "r") as fo:
            old_results = json.load(fo)
        parser_name = old_results["parser"]

        file_path = get_path_in_malware_repo(md5=self.md5)
        if not file_path.exists():
            logger.warning(f"Unable to update {self.name}. Missing {file_path}")
            return False

        report = mwcp.run(parser_name, data=file_path.read_bytes(), log_level=logging.INFO)
        if report.errors and not force:
            logger.warning(f"Results for {self.name} has the following errors, not updating:")
            logger.warning("\n".join(report.errors))
            return False

        # Don't bother updating if it only updates the mwcp version.
        new_results = report.as_json_dict()
        new_results["mwcp_version"] = old_results["mwcp_version"]
        if new_results == old_results:
            return True

        logger.info(f"Updating results for {file_path} in {results_path}")
        results_path.write_text(report.as_json())
        return True


def get_path_in_malware_repo(file_path: Union[str, pathlib.Path] = None, md5: str = None) -> pathlib.Path:
    """
    Gets file path for a file in the malware_repo based on the given md5 or md5 of the given file_path.

    :param file_path: Path to file to hash in order to obtain the equivalent file path in the malware repo.
    :param md5: All or partial md5 of sample to get from malware repo.

    :raises ValueError: If sample doesn't exists in malware repo.
    """
    malware_repo = mwcp.config.get("MALWARE_REPO")
    if not malware_repo:
        raise ValueError(f"MALWARE_REPO field not set in '{mwcp.config.user_path}'. Try running `mwcp config` to set this.")
    if file_path:
        with open(file_path, "rb") as fo:
            md5 = hashlib.md5(fo.read()).hexdigest()
    if not md5:
        raise ValueError(f"Missing file_path or md5 parameter.")

    # If md5 is partial, try to figure out which md5 we want by iterating the directory.
    if len(md5) < 4:
        raise ValueError(f"Unable to determine md5 from '{md5}'. Must be at least 4 characters.")

    if len(md5) < 32:
        sub_dir = pathlib.Path(malware_repo, md5[:4])
        if not sub_dir.exists():
            raise ValueError(f"Failed to find sample starting with the md5 '{md5}'.")
        file_paths = []
        for file_path in sub_dir.iterdir():
            if file_path.name.startswith(md5):
                file_paths.append(file_path)
        if not file_paths:
            raise ValueError(f"Failed to find sample starting with the md5 '{md5}'.")
        if len(file_paths) > 1:
            md5s = "\t\n".join(file_path.name for file_path in file_paths)
            raise ValueError(f"Found multiple samples starting with  the md5 '{md5}': \n\t{md5s}")
        return file_paths[0]

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


def iter_test_cases(source: registry.Source = None, parsers: List[str] = None) -> Iterable[TestCase]:
    """
    Iterates the test cases discovered from a specific or all registered sources.

    :param source: Optional source to obtain test cases for.
    :param parsers: List of parser names for tests cases.
    :yields: tests cases
    """
    # If parser names provided, iterate test cases just for those parsers.
    if parsers:
        cache = set()
        for parser_name in parsers:
            if source:
                for test_case in iter_test_cases(source):
                    if parser_name in test_case.name:
                        yield test_case
            else:
                for source, parser in mwcp.iter_parsers(parser_name):
                    if source not in cache:
                        cache.add(source)
                        for test_case in iter_test_cases(source):
                            if parser_name in test_case.name:
                                yield test_case
        return

    testcase_dirs = []
    # First see if user provided a global testcase directory that overrides all sources.
    # Test case directories are organized into sub directories based on source name.
    testcase_dir = mwcp.config.get("TESTCASE_DIR")
    if testcase_dir:
        testcase_dir = pathlib.Path(testcase_dir)
        for source_dir in testcase_dir.iterdir():
            if source_dir.is_dir() and registry.is_source(source_dir.name):
                testcase_dirs.append((source_dir.name, source_dir))

        # If we don't find any testcase directories, user probably provided a directory
        # not structured as expected.
        # In this case, let's just recursively look for all .json files.
        if not testcase_dirs:
            for file_path in testcase_dir.glob("**/[!_]*.json"):
                with open(file_path, "r") as fp:
                    data = json.load(fp)
                try:
                    yield TestCase(data["parser"], data["input_file"]["md5"], file_path)
                except (KeyError, TypeError):
                    logger.warning(f"Failed to collect testcase file: {file_path}")
            return

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


def iter_failed_tests() -> Iterable[TestCase]:
    """
    Iterates the previously failed test cases.
    """
    lastfailed_file = mwcp.config.pytest_cache_dir / "v" / "cache" / "lastfailed"
    if lastfailed_file.exists():
        with open(lastfailed_file, "r") as fo:
            data = json.load(fo)
        for key, enabled in data.items():
            if enabled:
                identifier = re.search("\[(.*)\]", key).group(1)
                parser_name, found, md5 = identifier.partition("-")
                if found:
                    for test_case in iter_test_cases():
                        if test_case.name == parser_name and test_case.md5 == md5:
                            yield test_case
                            break


def iter_md5s(parser_name: str) -> Iterable[str]:
    """
    Obtains the md5 hashes for the test cases for a given parser name

    :param parser_name: Name of parser (case-sensitive)
    :yields: md5 hashes
    """
    for test_case in iter_test_cases(parsers=[parser_name]):
        _, _, test_case_name = test_case.name.partition(":")
        if test_case_name == parser_name:
            yield test_case.md5


def download(md5: str, output_dir: pathlib.Path = None):
    """
    Downloads test sample for given md5.

    :param md5: Full or partial md5 hash.
    :param output_dir: Directory to write file. (defaults to current directory)
    :return: Path of downloaded file.

    :raise IOError: If file could not be found.
    """
    if not output_dir:
        output_dir = pathlib.Path(".")
        
    try:
        file_path = get_path_in_malware_repo(md5=md5)
    except ValueError as e:
        raise IOError(e)

    if not file_path.exists():
        raise IOError(f"Unable to find sample at {file_path}")

    output_path = output_dir / file_path.name
    logger.debug(f"Downloading {file_path}...")
    with open(output_path, "wb") as fo:
        fo.write(file_path.read_bytes())
    return output_path


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
