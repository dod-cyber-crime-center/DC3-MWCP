"""
Test case support for DC3-MWCP. Parser output is stored in a json file per parser. To run test cases,
parser is re-run and compared to previous results.
"""

import json
import multiprocessing as mp
import logging
import os
import pathlib
import sys
import traceback
from timeit import default_timer

try:
    import pkg_resources
except ImportError:
    pkg_resources = None

import mwcp
from mwcp import config
from mwcp.utils.stringutils import convert_to_unicode
from mwcp.utils import multi_proc

logger = logging.getLogger(__name__)

# Constants
DEFAULT_EXCLUDE_FIELDS = (u"debug",)
INPUT_FILE_PATH = u"inputfilename"  # MUST BE UNICODE
FILE_EXTENSION = ".json"

# Setting encoding to utf8 is a hotfix for a larger issue
encode_params = {"encoding": "utf8", "errors": "replace"}


def multiproc_test_wrapper(args):
    """Wrapper function for running tests in multiple processes."""
    test_case = args[0]
    try:
        return test_case.run(*args[1:])
    except KeyboardInterrupt:
        return


class Tester(object):
    """DC3-MWCP Tester class"""

    def __init__(
        self, parser_names=None, nprocs=None, field_names=None, ignore_field_names=DEFAULT_EXCLUDE_FIELDS,
    ):
        """

        Run tests and compare produced results to expected results.

        :param [str] parser_names:
                A list of parser names to run tests for. If the list is empty (default),
                then test cases for all parsers will be run.
        :param [str] field_names:
                A restricted list of fields (metadata key values) that should be compared
                during testing. If the list is empty (default), then all fields, except those in
                ignore_field_names will be compared.
        :param int nprocs: Number of processes to use. (defaults to (3*num_cores)/4)
        """
        self.field_names = field_names or []
        self.ignore_field_names = ignore_field_names
        self._test_cases = None
        self._results = []  # Cached results.
        self._processed = False
        self._nprocs = nprocs or (3 * mp.cpu_count()) // 4
        if not parser_names or parser_names == [None]:
            parser_names = [f"{source.name}:{parser.name}" for source, parser in mwcp.iter_parsers()]
        self.parser_names = parser_names

    def __iter__(self):
        return self._iter_results()

    def _iter_results(self):
        # First yield any cached results.
        for result in self._results:
            yield result

        # Run tests in multiprocessing pool (if not already run)
        if not self._processed:
            self._processed = True
            pool = multi_proc.TPool(processes=self._nprocs)
            test_iter = pool.imap_unordered(multiproc_test_wrapper, [(test_case,) for test_case in self.test_cases])
            pool.close()

            try:
                for result in test_iter:
                    self._results.append(result)
                    yield result
            except KeyboardInterrupt:
                pool.terminate()
                raise

    @property
    def test_cases(self):
        """Returns test cases."""
        if self._test_cases is None:
            self._test_cases = []
            for parser_name in self.parser_names:
                # We want to iterate parsers in case parser_name represents a set of parsers from different sources.
                found = False
                for source, parser in mwcp.iter_parsers(parser_name):
                    found = True
                    full_parser_name = "{}:{}".format(source.name, parser.name)
                    results_file_path = self.get_results_filepath(full_parser_name)
                    if os.path.isfile(results_file_path):
                        for expected_results in self.read_results_file(results_file_path):
                            self._test_cases.append(
                                TestCase(
                                    full_parser_name,
                                    expected_results,
                                    field_names=self.field_names,
                                    ignore_field_names=self.ignore_field_names,
                                )
                            )
                    else:
                        # Warn user if they are missing a test file for a parser group.
                        logger.warning("Test case file not found: {}".format(results_file_path))

                if not found and parser_name:
                    # Add a failed results if we have an orphan test.
                    self._results.append(TestResult(parser=parser_name, passed=False, errors=["Parser not found."]))
        return self._test_cases

    @property
    def total(self):
        """Returns total number of results."""
        return len(self._results) + len(self.test_cases)

    def gen_results(self, parser_name, input_file_path):
        """
        Generate JSON results for the given file using the given parser name.
        """
        report = mwcp.run(parser_name, input_file_path)
        results = report.metadata
        results[INPUT_FILE_PATH] = convert_to_unicode(input_file_path)
        return report, results

    def _list_test_files(self, results_list):
        """
        Returns a list of the input file paths for the given results_list.
        """
        return [results[INPUT_FILE_PATH] for results in results_list]

    def get_results_filepath(self, name, source=None):
        """
        Returns the results file path based on the parser name provided and the
        set testcase directory.
        """
        for source, parser in mwcp.iter_parsers(name, source=source):
            file_name = parser.name + FILE_EXTENSION
            # Use hardcoded testcase directory if set.
            testcase_dir = mwcp.config.get("TESTCASE_DIR")
            if testcase_dir:
                return os.path.join(testcase_dir, file_name)

            if source.is_pkg:
                # Dynamically pull based on parser's top level module.
                test_dir = pkg_resources.resource_filename(source.path, "tests")
            else:
                # If source is a directory, assume there is a "tests" folder within it.
                test_dir = os.path.join(source.path, "tests")

            return os.path.normpath(os.path.join(test_dir, file_name))

        raise ValueError("Invalid parser: {}".format(name))

    def read_results_file(self, results_file_path):
        """
        Parses and validates the JSON results file and returns the parsed results_dict.
        """
        if not os.path.exists(results_file_path):
            results = []
        else:
            with open(results_file_path) as results_file:
                results = json.load(results_file)

        # The results file results_dict is expected to be a list of metadata dictionaries
        if not isinstance(results, list) or not all(isinstance(a, dict) for a in results):
            raise ValueError("Results file is invalid: {}".format(results_file_path))

        # Resolve input file paths.
        for testcase in results:
            # NOTE: Using PureWindowsPath to help convert a Windows path using \
            #   into / path.
            #   This helps in-case the test case was originally made with a Windows machine
            #   but is being tested on Linux.
            input_file_path = pathlib.PureWindowsPath(testcase[INPUT_FILE_PATH]).as_posix()
            # expand environment variables
            input_file_path = os.path.expandvars(input_file_path)
            # resolve variables
            input_file_path = input_file_path.format(MALWARE_REPO=mwcp.config.get("MALWARE_REPO", ""))
            # make relative paths relative to json file
            input_file_path = os.path.join(os.path.dirname(results_file_path), input_file_path)
            input_file_path = os.path.abspath(input_file_path)
            testcase[INPUT_FILE_PATH] = input_file_path

        return results

    def write_results_file(self, results_list, file_path):
        """
        Saves the JSON results list to the given file path.
        :param list[dict] results_list: JSON results list to save
        :param str file_path: Path to save the results JSON file.
        """
        # Replace references to the malware repo with a variable.
        malware_repo = mwcp.config.get("MALWARE_REPO", None)
        if malware_repo:
            for results in results_list:
                # TODO: Refactor this
                input_file_path = results[INPUT_FILE_PATH]
                if input_file_path.startswith(malware_repo):
                    input_file_path = "{MALWARE_REPO}" + input_file_path[len(malware_repo) :]
                results[INPUT_FILE_PATH] = input_file_path

        # Write updated data to results file
        # NOTE: We need to use dumps instead of dump to avoid TypeError.
        with open(file_path, "w", encoding="utf8") as results_file:
            results_file.write(str(json.dumps(results_list, indent=4, sort_keys=True)))

    def update_tests(self, force=False):
        """
        Updates existing test cases by rerunning parsers.

        :param bool force: Whether to force adding the test case even if errors are encountered
        """
        orig_level = logging.root.level
        logging.root.setLevel(logging.INFO)  # Force info level logs so test cases stay consistent.
        try:
            for parser_name in self.parser_names:
                logger.info(f"Updating test for parser: {parser_name}")
                results_file_path = self.get_results_filepath(parser_name)
                if not os.path.isfile(results_file_path):
                    logger.warning(f"No test case file found for parser: {results_file_path}")
                    continue
                results_list = self.read_results_file(results_file_path)
                for index, file_path in enumerate(self._list_test_files(results_list)):
                    report, new_results = self.gen_results(parser_name, file_path)
                    if not new_results:
                        logger.warning("Empty results for {} in {}, not updating.".format(file_path, results_file_path))
                        continue
                    if report.errors and not force:
                        logger.warning("Results for {} has errors, not updating.".format(file_path))
                        continue

                    logger.info("Updating results for {} in {}".format(file_path, results_file_path))
                    results_list[index] = new_results

                self.write_results_file(results_list, results_file_path)
        finally:
            logging.root.setLevel(orig_level)

    def add_test(self, file_path, force=False, update=False):
        """
        Adds test case for given file path.

        :param str file_path: Path to input file to add.
        :param bool force: Whether to force adding the test case even if errors are encountered
        :param bool update: Whether to allow updating the test case if a test for this file already exists.
        """
        orig_level = logging.root.level
        logging.root.setLevel(logging.INFO)  # Force info level logs so test cases stay consistent.
        try:
            for parser_name in self.parser_names:
                results_file_path = self.get_results_filepath(parser_name)
                results_list = self.read_results_file(results_file_path)
                input_files = self._list_test_files(results_list)

                if file_path in input_files and not update:
                    logger.warning("Test case for {} already exists in {}".format(file_path, results_file_path))
                    continue

                report, new_results = self.gen_results(parser_name, file_path)
                if not new_results:
                    logger.warning("Empty results for {} in {}, not adding.".format(file_path, results_file_path))
                    continue
                if report.errors and not force:
                    logger.warning("Results for {} has errors, not adding.".format(file_path))
                    continue

                if file_path in input_files:
                    logger.info("Updating results for {} in {}".format(file_path, results_file_path))
                    index = input_files.index(file_path)
                    results_list[index] = new_results
                else:
                    logger.info("Adding results for {} in {}".format(file_path, results_file_path))
                    results_list.append(new_results)

                self.write_results_file(results_list, results_file_path)
        finally:
            logging.root.setLevel(orig_level)

    def remove_test(self, file_path):
        """Removes test case for given file path."""
        for parser_name in self.parser_names:
            results_file_path = self.get_results_filepath(parser_name)
            results_list = []
            removed = False
            for results in self.read_results_file(results_file_path):
                if results[INPUT_FILE_PATH] == file_path:
                    logger.info("Removed results for {} in {}".format(file_path, results_file_path))
                    removed = True
                else:
                    results_list.append(results)

            if removed:
                self.write_results_file(results_list, results_file_path)


class TestCase(object):
    def __init__(self, parser, expected_results, field_names=None, ignore_field_names=DEFAULT_EXCLUDE_FIELDS):
        self.input_file_path = expected_results[INPUT_FILE_PATH]
        self.filename = os.path.basename(self.input_file_path)
        self.parser = parser
        self.parser_source, _, self.parser_name = parser.rpartition(":")
        self.expected_results = expected_results
        self._field_names = field_names or []
        self._ignore_field_names = ignore_field_names or []

    def run(self):
        """Run test case."""
        start_time = default_timer()

        # Clear any existing loggers to ensure the only logs present are in
        # the report.
        logging.root.handlers.clear()

        report = mwcp.run(self.parser, self.input_file_path, log_level=logging.INFO)
        results = report.metadata
        results[INPUT_FILE_PATH] = convert_to_unicode(self.input_file_path)

        comparer_results = self._compare_results(self.expected_results, results)
        passed = all(comparer.passed for comparer in comparer_results)

        done_time = default_timer()
        run_time = done_time - start_time

        return TestResult(
            parser=self.parser,
            input_file_path=self.input_file_path,
            passed=passed,
            errors=report.errors,
            debug=report.logs or None,
            results=comparer_results,
            run_time=run_time,
        )

    def _compare_results(self, results_a, results_b):
        """
        Compare two result sets. If the field names list is not empty,
        then only the fields (metadata key values) in the list will be compared.
        ignore_field_names fields are not compared unless included in field_names.
        """
        results = []

        # Cursory check to remove FILE_INPUT_PATH key from results since it is
        # a custom added field for test cases
        if INPUT_FILE_PATH in results_a:
            results_a = dict(results_a)
            del results_a[INPUT_FILE_PATH]
        if INPUT_FILE_PATH in results_b:
            results_b = dict(results_b)
            del results_b[INPUT_FILE_PATH]

        # Begin comparing results
        if self._field_names:
            for field_name in self._field_names:
                try:
                    comparer = self._compare_results_field(results_a, results_b, field_name)
                except:
                    comparer = ResultComparer(field_name)
                    logger.error(traceback.format_exc())
                results.append(comparer)
        else:
            for ignore_field in self._ignore_field_names:
                results_a.pop(ignore_field, None)
                results_b.pop(ignore_field, None)
            all_field_names = set(results_a.keys()).union(list(results_b.keys()))
            for field_name in all_field_names:
                try:
                    comparer = self._compare_results_field(results_a, results_b, field_name)
                except:
                    comparer = ResultComparer(field_name)
                    logger.error(traceback.format_exc())
                results.append(comparer)

        return results

    def _compare_results_field(self, results_a, results_b, field_name):
        """
        Compare the values for a single results field in the two passed in results.

        Args:
            results_a (dict): MWCP generated result for a given file using a given parser.
            results_b (dict): MWCP generated result for a given file using a given parser.
        """

        # Check if provided field_name is a valid key (based on fields.json)
        try:
            field_name_u = convert_to_unicode(field_name)
        except:
            raise Exception("Failed to convert field name '{}' to unicode.".format(field_name))

        # Stolen from Reporter/Runner.
        # TODO: Look into refactoring to use pytest entirely?
        with open(config.get("FIELDS_PATH"), "rb") as f:
            fields = json.load(f)

        try:
            field_type = fields[field_name_u]["type"]
        except:
            raise Exception("Key error. Field name '{}' was not identified as a standardized field.".format(field_name))

        # Establish value to send for comparison
        value_a = None
        value_b = None
        if field_name_u in results_a:
            value_a = results_a[field_name_u]
        if field_name_u in results_b:
            value_b = results_b[field_name_u]

        # Now compare results based on field type (see "fields.json" for more
        # details)
        if field_type == "listofstrings":
            comparer = ListOfStringsComparer(field_name_u)
            comparer.compare(value_a, value_b)
        elif field_type == "listofstringtuples":
            comparer = ListOfStringTuplesComparer(field_name_u)
            comparer.compare(value_a, value_b)
        elif field_type == "dictofstrings":
            comparer = DictOfStringsComparer(field_name_u)
            comparer.compare(value_a, value_b)
        else:
            raise Exception("Unhandled field type '{}' found for field name '{}'.".format(field_type, field_name))

        return comparer


class TestResult(object):
    def __init__(self, parser, passed, input_file_path=None, errors=None, debug=None, results=None, run_time=None):
        self.parser = parser
        self.parser_source, _, self.parser_name = parser.rpartition(":")
        self.input_file_path = input_file_path or "N/A"
        self.filename = os.path.basename(input_file_path) if input_file_path else "N/A"
        self.passed = passed
        self.errors = errors or []
        self.debug = debug or []
        self.results = results or []
        self.run_time = run_time or 0

    def print(self, failed_tests=True, passed_tests=True, json_format=False):
        """
        print test result based on provided parameters.

        :param bool failed_tests: Whether to show failed tests.
        :param bool passed_tests: Whether to show passed tests.
        :param bool json_format: Whether to format results as json.
        """
        # TODO: Do we need the json option?
        if json_format:
            passed = self.passed
            if (passed and passed_tests) or (not passed and failed_tests):
                print(json.dumps(self, indent=4, cls=MyEncoder))
        else:
            separator = ""

            filtered_output = ""
            passed = self.passed
            if passed and passed_tests:
                filtered_output += "Parser Name = {}\n".format(self.parser)
                if self.input_file_path and self.input_file_path != "N/A":
                    filtered_output += "Input Filename = {}\n".format(self.input_file_path)
                filtered_output += "Tests Passed = {}\n".format(self.passed)
            elif not passed and failed_tests:
                filtered_output += "Parser Name = {}\n".format(self.parser)
                if self.input_file_path and self.input_file_path != "N/A":
                    filtered_output += "Input Filename = {}\n".format(self.input_file_path)
                filtered_output += "Tests Passed = {}\n".format(self.passed)
                filtered_output += "Errors = {}".format("\n" if self.errors else "None\n")
                if self.errors:
                    for entry in self.errors:
                        filtered_output += "\t{0}\n".format(entry)
                filtered_output += "Debug Logs = {}".format("\n" if self.debug else "None\n")
                if self.debug:
                    for entry in self.debug:
                        filtered_output += "\t{0}\n".format(entry)
                if self.results:
                    filtered_output += "Results =\n"
                    for result in self.results:
                        if not result.passed:
                            filtered_output += "{0}\n".format(result)

            if filtered_output:
                filtered_output += "{0}\n".format(separator)
                print(filtered_output.encode("ascii", "backslashreplace").decode())


####################################################
# Comparer classes for various MWCP field types
####################################################


class ResultComparer(object):
    def __init__(self, field):
        self.field = field
        self.passed = False
        self.missing = []  # Entries found in test case but not new results
        self.unexpected = []  # Entries found in new results but not test case

    def compare(self, test_case_results=None, new_results=None):
        """Compare two result sets and document any differences."""

        self.missing = []
        self.unexpected = []

        self.field_compare(test_case_results, new_results)

        self.passed = not bool(self.missing or self.unexpected)

    def field_compare(self, test_case_results, new_results):
        """Field specific compare function."""
        # Override in child classes
        raise NotImplementedError()

    def get_report(self, json=False, tabs=1):
        """
        If json parameter is False, get report as a unicode string.
        If json parameter is True, get report as a dictionary.
        """

        if json:
            return self.__dict__
        else:
            tab = tabs * "\t"
            tab_1 = tab + "\t"
            tab_2 = tab_1 + "\t"
            report = tab + "{}:\n".format(self.field)
            report += tab_1 + "Passed: {}\n".format(self.passed)
            if self.missing:
                report += tab_1 + "Missing From New Results:\n"
                for item in self.missing:
                    report += tab_2 + "{}\n".format(convert_to_unicode(item))
            if self.unexpected:
                report += tab_1 + "Unexpected New Results:\n"
                for item in self.unexpected:
                    report += tab_2 + "{}\n".format(convert_to_unicode(item))

            return report

    def __bytes__(self):
        return self.get_report().encode("utf8")

    def __unicode__(self):
        return self.get_report()

    def __str__(self):
        if sys.version_info >= (3, 0):
            return self.__unicode__()
        else:
            return self.__bytes__()

    def __repr__(self):
        return self.__str__()


class ListOfStringsComparer(ResultComparer):
    def field_compare(self, test_case_results, new_results):
        """Compare each string in a list of strings."""
        list_test = [] if not test_case_results else test_case_results
        list_new = [] if not new_results else new_results

        self.missing += list(map(repr, set(list_test) - set(list_new)))
        self.unexpected += list(map(repr, set(list_new) - set(list_test)))


class ListOfStringTuplesComparer(ResultComparer):
    def field_compare(self, test_case_results, new_results):
        """Compare each tuple of strings in a list of tuples."""
        set_list_test = []
        set_list_new = []
        if test_case_results:
            set_list_test = [set(x) for x in test_case_results]
        if new_results:
            set_list_new = [set(x) for x in new_results]

        for set_test in set_list_test:
            if set_test not in set_list_new:
                # Append the list entry here instead of the set to preserve the
                # entries ordering
                self.missing.append(repr(test_case_results[set_list_test.index(set_test)]))

        for set_new in set_list_new:
            if set_new not in set_list_test:
                # Append the list entry here instead of the set to preserve the
                # entries ordering
                self.unexpected.append(repr(new_results[set_list_new.index(set_new)]))


class DictOfStringsComparer(ResultComparer):
    def field_compare(self, test_case_results, new_results):
        """Compare each key value pair in a dictionary of strings."""
        dict_test = {} if not test_case_results else test_case_results
        dict_new = {} if not new_results else new_results

        for key in dict_test:
            if key not in dict_new:
                self.missing.append(u"{}: {!r}".format(key, dict_test[key]))
            elif set(dict_test[key]) != set(dict_new[key]):
                self.missing.append(u"{}: {!r}".format(key, dict_test[key]))

        for key in dict_new:
            if key not in dict_test:
                self.unexpected.append(u"{}: {!r}".format(key, dict_new[key]))
            elif set(dict_new[key]) != set(dict_test[key]):
                self.unexpected.append(u"{}: {!r}".format(key, dict_new[key]))


####################################################
# JSON encoders
####################################################


class MyEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__
