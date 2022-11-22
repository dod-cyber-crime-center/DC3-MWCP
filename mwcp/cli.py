"""
DC3-MWCP Framework command line tool.

Used for running and testing parsers.
"""

from __future__ import print_function, division

import pathlib
import shlex
from typing import Tuple

import pandas
import pytest
from future.builtins import str, zip

import csv
import datetime
import glob
import hashlib
from io import open
import itertools
import json
import logging
import os
import shutil
import subprocess
import sys
import timeit
import traceback
import warnings

import click
import six
import tabulate

import mwcp
from mwcp import testing
from mwcp.stix.report_writer import STIXWriter
from mwcp.tester import Tester
from mwcp.utils.stringutils import convert_to_unicode

logger = logging.getLogger("mwcp")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("-d", "--debug", is_flag=True, help="Enables DEBUG level logs.")
@click.option("-v", "--verbose", is_flag=True, help="Enables INFO level logs.")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    help="File path to configuration file.",
    default=mwcp.config.user_path,
    show_default=True,
    envvar="MWCP_CONFIG",
    show_envvar=True,
)
@click.option(
    "--parser-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Optional extra parser directory.",
)
@click.option(
    "--parser-config",
    type=click.Path(exists=True, dir_okay=False),
    help="Optional parser configuration file to use with extra parser directory.",
)
@click.option(
    "--parser-source",
    help="Set a default parsers source to use. If not provided parsers from all sources will be available.",
)
def main(debug, verbose, config_path, parser_dir, parser_config, parser_source):
    # Setup configuration
    mwcp.config.load(config_path)
    if parser_dir:
        mwcp.config["PARSER_DIR"] = parser_dir
    parser_dir = mwcp.config.get("PARSER_DIR")
    if parser_config:
        mwcp.config["PARSER_CONFIG_PATH"] = parser_config
    parser_config = mwcp.config.get("PARSER_CONFIG_PATH")
    if parser_source:
        mwcp.config["PARSER_SOURCE"] = parser_source
    parser_source = mwcp.config.get("PARSER_SOURCE")

    # Setup logging
    mwcp.setup_logging()
    if debug:
        logging.root.setLevel(logging.DEBUG)
    elif verbose:
        logging.root.setLevel(logging.INFO)
    # else let log_config.yaml set log level.

    # Register parsers
    mwcp.register_entry_points()
    if parser_dir:
        mwcp.register_parser_directory(parser_dir, config_file_path=parser_config)
    if parser_source:
        mwcp.set_default_source(parser_source)


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="The interface to bind to.")
@click.option("--port", default=8080, show_default=True, help="The port to bind to.")
@click.option("--debug", is_flag=True, help="Show the interactive debugger if errors occur.")
def serve(host, port, debug):
    """Run a server to handle parsing requests."""
    from mwcp.tools import server

    if debug:
        os.environ["FLASK_ENV"] = "development"

    app = server.create_app()
    app.run(host=host, port=port, debug=debug, use_reloader=False)


@main.command()
def config():
    """Opens up configuration file for editing."""
    file_path = mwcp.config.user_path
    if sys.platform == "win32":
        try:
            os.startfile(file_path, "edit")
        except WindowsError:
            os.startfile(file_path)
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.call([opener, file_path])

    # TODO: Add a "-u" flag to this command when we need to update the user's configuration file
    # with new fields.


@main.command("list")
@click.option(
    "-a",
    "--all",
    "all_",
    is_flag=True,
    help="Whether to also include parsers not listed in any parsers configuration file.",
)
@click.option("-j", "--json", "json_", is_flag=True, help="Display as JSON output.")
def list_(all_, json_):
    """Lists registered malware config parsers."""
    descriptions = mwcp.get_parser_descriptions(config_only=not all_)
    if json_:
        print(json.dumps(descriptions, indent=4))
    else:
        print(tabulate.tabulate(descriptions, headers=["NAME", "SOURCE", "AUTHOR", "DESCRIPTION"]))


# Column order for standard fields in csv.
# (All other fields will be appended in alphabetical order after these)
_STD_CSV_COLUMNS = [
    "scan_date",
    "inputfilename",
    "outputfile.name",
    "outputfile.description",
    "outputfile.md5",
    "outputfile.base64",
]


def _format_metadata_value(v):
    """Formats metadata value to a human readable unicode string."""
    if isinstance(v, (list, tuple)):
        result = u""
        for j in v:
            if not isinstance(j, (bytes, str)):
                result += u"{}\n".format(u", ".join(map(convert_to_unicode, j)))
            else:
                result += u"{}\n".format(convert_to_unicode(j))
        return result.rstrip()
    elif isinstance(v, dict):
        result = u""
        for field, value in six.iteritems(v):
            if isinstance(value, (list, tuple)):
                value = u"[{}]".format(u", ".join(value))

            result += u"{}: {}\n".format(field, value)
        return result.rstrip()
    else:
        return convert_to_unicode(v)


def _write_csv(input_files, results, csv_path=None):
    """
    Writes out results as a csv.

    :param input_files: List of filenames for each respective metadata.
    :param results: List of metadata dictionaries.
    :param csv_path: Path to write out csv file, defaults to stdout.

    :raises IOError: If csv could not be written out.
    """
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Add/Teak metadata.
    for inputfilename, metadata in zip(input_files, results):
        # Add scan date.
        metadata[u"scan_date"] = scan_date
        if u"inputfilename" not in metadata:
            metadata[u"inputfilename"] = inputfilename

        # Flatten 'other' entry so nested values get their own columns,
        # are more readable, and easier to individually analyze.
        #
        # Example:
        #   {'other': {"unique_entry": "value", "unique_key": "value2"}}
        #   Results in columns: other, other.unique_entry, other.unique_key
        if u"other" in metadata:
            for sub_key, sub_value in metadata[u"other"].items():
                metadata[u"other.{}".format(convert_to_unicode(sub_key))] = sub_value
            del metadata[u"other"]

        # Split outputfile into multiple fields.
        if u"outputfile" in metadata:
            value = list(zip(*metadata[u"outputfile"]))
            metadata[u"outputfile.name"] = value[0]
            metadata[u"outputfile.description"] = value[1]
            metadata[u"outputfile.md5"] = value[2]
            del metadata[u"outputfile"]

    # Sort columns, but with PREFIX_COLUMNS showing up first.
    column_names = set(itertools.chain(*(metadata.keys() for metadata in results)))
    column_names = sorted(
        column_names, key=lambda x: str(_STD_CSV_COLUMNS.index(x)) if x in _STD_CSV_COLUMNS else str(x)
    )

    # Reformat metadata and write to CSV
    if csv_path is None:
        csvfile = sys.stdout
    else:
        csvfile = open(csv_path, "wb" if six.PY2 else "w")

    try:
        dw = csv.DictWriter(csvfile, fieldnames=column_names, lineterminator="\n")
        dw.writeheader()
        for metadata in results:
            dw.writerow({k: _format_metadata_value(v) for k, v in metadata.items()})
    finally:
        if csv_path:
            csvfile.close()


@main.command()
@click.option(
    "--yara-repo",
    type=click.Path(file_okay=False),
    help="Directory containing YARA signatures used for auto detection.",
)
@click.option(
    "--recursive/--no-recursive",
    default=True,
    show_default=True,
    help="Whether to recursively parse unidentified residual files using YARA match. "
         "(Only works if a YARA repo has been provided through command line or configuration)"
)
@click.option(
    "-f", "--format",
    type=click.Choice(["csv", "json", "simple", "markdown", "html", "stix"]),
    default="simple",
    show_default=True,
    help="Displays results in another format.",
)
@click.option(
    "--split/--no-split",
    default=False,
    show_default=True,
    help="Whether to display results by source file the metadata originates from. "
         "By default, results are only consolidated based on original input file. "
         "(This feature is not available when --legacy is set.)"
)
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(exists=True, file_okay=False),
    help="Root output directory to store residual files. (defaults to current directory)",
)
@click.option(
    "--output-files/--no-output-files",
    default=True,
    show_default=True,
    help="Whether to output files to filesystem."
)
@click.option(
    "--prefix/--no-prefix",
    default=True,
    show_default=True,
    help="Whether to prefix output filenames with the first 5 characters of the md5. "
         "If turned off, unique files with the same file name will be overwritten."
)
@click.option(
    "--string-report/--no-string-report",
    default=False,
    show_default=True,
    help="Whether to report decoded strings into a separate external report output "
         "as a supplemental file."
)
@click.option(
    "-i",
    "--include-filename",
    is_flag=True,
    help="Include file information such as filename, hashes, and compile time in parser output. DEPRECATED",
)
@click.option(
    "--legacy/--no-legacy",
    default=False,
    show_default=True,
    help="Whether to present json output using legacy schema. "
         "(WARNING: This flag will eventually be removed in favor of only supporting the new schema.)"
)
@click.argument("parser", required=True)
@click.argument("input", nargs=-1, type=click.Path())
def parse(parser, input, yara_repo, recursive, format, split, output_dir, output_files, prefix, string_report, include_filename, legacy):
    """
    Parses given input with given parser.

    \b
    PARSER: Name of parser to run. (or "-" for YARA matching)
    INPUT: One or more input file paths. (Wildcards are allowed).

    \b
    Common usages::
        mwcp parse foo ./malware.bin                          - Run foo parser on ./malware.bin
        mwcp parse foo ./repo/*                               - Run foo parser on files found in repo directory.
        mwcp parse -f json foo ./malware.bin                  - Run foo parser and display results as json.
        mwcp parse -f csv foo ./repo/* > ./results.csv        - Run foo parser on a directory and output results as a csv file.
        mwcp parse - ./malware.bin --yara-repo=./rules        - Run a parser on ./malware.bin where the parser is detected by YARA.
        mwcp parse - ./malware.bin                            - yara_repo can be omitted if included in configuration.
    """
    if yara_repo:
        mwcp.config["YARA_REPO"] = yara_repo

    # Python won't process wildcards when used through Windows command prompt.
    if any("*" in path for path in input):
        new_input = []
        for path in input:
            if "*" in path:
                new_input.extend(glob.glob(path))
            else:
                new_input.append(path)
        input = new_input

    input_files = list(filter(os.path.isfile, input))
    output_dir = output_dir or ""

    # Run MWCP
    try:
        reports = []
        for path in input_files:
            config = dict(
                output_directory=os.path.join(output_dir, os.path.basename(path) + "_mwcp_output") if output_files else None,
                prefix_output_files=prefix,
                external_strings_report=string_report,
                recursive=recursive,
            )
            if parser == "-":
                parser = None
            logger.info("Parsing: {}".format(path))
            # TODO: This is temporary, make real fix.
            if path == "-":
                report = mwcp.run(parser, data=sys.stdin.read().encode(), **config)
            else:
                report = mwcp.run(parser, file_path=path, **config)
            reports.append(report)

        # TODO: Perhaps split up results with header of input file?
        if format in ("simple", "markdown", "html"):
            for report in reports:
                print(report.as_text(format, split=split))

        elif format == "json":
            if legacy:
                results = [report.as_dict_legacy(include_filename=include_filename) for report in reports]
            else:
                results = []
                for report in reports:
                    if split:
                        results.extend(report.as_json_dict(split=True))
                    else:
                        results.append(report.as_json_dict())
            print(json.dumps(results, indent=4))

        elif format == "csv":
            if legacy:
                _write_csv(input_files, [report.metadata for report in reports])
            else:
                # TODO: Determine a more elegant way to handle multiple reports and split/non-split reports
                #   writing to the same stream/df.
                if len(reports) == 1:
                    df = reports[0].as_dataframe(split=split)
                else:
                    df = pandas.concat([report.as_dataframe(split=split) for report in reports])
                print(df.to_csv(line_terminator="\n"))

        elif format == "stix":
            writer = STIXWriter()

            # aggregate the report details
            for report in reports:
                report.as_stix(writer)
                
            print(writer.serialize())

    except Exception as e:
        error_message = "Error running DC3-MWCP: {}".format(e)
        traceback.print_exc()
        if format == "json":
            print(json.dumps({"errors": [error_message]}))
        else:
            print(error_message)
        sys.exit(1)


def _read_input_list(filename):
    inputfilelist = []
    if filename:
        if filename == "-":
            inputfilelist = [line.rstrip() for line in sys.stdin]
        else:
            with open(filename, "rb") as f:
                inputfilelist = [line.rstrip() for line in f]

    return inputfilelist


def _median(data):
    """
    'Borrowed' from Py3's statistics library.

    :param data: Data to get median of
    :return: Median as a float or int
    :rtype: float or int
    """
    data = sorted(data)
    length = len(data)
    if length == 0:
        raise ValueError("No median for empty data.")
    elif length % 2 == 1:
        return data[length // 2]
    else:
        i = length // 2
        return (data[i - 1] + data[i]) / 2


def _run_tests(tester, silent=False, show_passed=False):
    print("Running test cases. May take a while...")

    start_time = timeit.default_timer()
    test_results = []
    all_passed = True
    total = tester.total
    failed = []

    # Generate format string.
    digits = len(str(total))
    if not tester.test_cases:
        parser_len = 10
        filename_len = 10
    else:
        parser_len = max(len(test_case.parser) for test_case in tester.test_cases)
        filename_len = max(len(test_case.filename) for test_case in tester.test_cases)
    msg_format = "{{parser:{0}}} {{filename:{1}}} {{run_time:.4f}}s".format(parser_len, filename_len)

    format_str = "{{count:> {0}d}}/{{total:0{0}d}} - ".format(digits) + msg_format

    # Run tests and output progress results.
    for count, test_result in enumerate(tester, start=1):
        all_passed &= test_result.passed
        if not test_result.passed:
            failed.append((count, test_result.parser, test_result.filename))

        if test_result.run_time:  # Ignore missing tests from stat summary.
            test_results.append(test_result)

        if not silent:
            message = format_str.format(
                count=count,
                total=total,
                parser=test_result.parser,
                filename=test_result.filename,
                run_time=test_result.run_time,
            )
            # Skip print() to immediately flush stdout buffer (issue in Docker containers)
            sys.stdout.write(message + "\n")
            sys.stdout.flush()
            test_result.print(failed_tests=True, passed_tests=show_passed)

    end_time = timeit.default_timer()

    # Present test statistics
    if not silent and test_results:
        print("\nTest stats:")
        print("\nTop 10 Slowest Test Cases:")

        format_str = "{index:2}. " + msg_format

        # Cases sorted slowest first
        sorted_cases = sorted(test_results, key=lambda x: x.run_time, reverse=True)
        for i, test_result in enumerate(sorted_cases[:10], start=1):
            print(
                format_str.format(
                    index=i, parser=test_result.parser, filename=test_result.filename, run_time=test_result.run_time
                )
            )

        print("\nTop 10 Fastest Test Cases:")
        for i, test_result in enumerate(list(reversed(sorted_cases))[:10], start=1):
            print(
                format_str.format(
                    index=i, parser=test_result.parser, filename=test_result.filename, run_time=test_result.run_time
                )
            )

        run_times = [test_result.run_time for test_result in test_results]
        print("\nMean Running Time: {:.4f}s".format(sum(run_times) / len(test_results)))
        print("Median Running Time: {:.4f}s".format(_median(run_times)))
        print("Cumulative Running Time: {}".format(datetime.timedelta(seconds=sum(run_times))))
        print()

    print("Total Running Time: {}".format(datetime.timedelta(seconds=end_time - start_time)))

    if failed:
        print()
        print("Failed tests:")
        for test_info in failed:
            print("#{} - {}\t{}".format(*test_info))
        print()

    print("All Passed = {0}\n".format(all_passed))
    exit(0 if all_passed else 1)


@main.command()
@click.option(
    "-t",
    "--testcase-dir",
    type=click.Path(file_okay=False),
    help="Directory containing JSON test case files. (defaults to a "
    '"tests" directory located within the parsers directory)',
)
@click.option(
    "-m",
    "--malware-repo",
    type=click.Path(file_okay=False),
    help="Directory containing malware samples used for testing.",
)
# Arguments used for run test cases.
@click.option(
    "-n", "--nprocs", type=int,
    help="Number of test cases to run simultaneously. [default: 3/4 * logical CPU cores]"
)
# Arguments used to generate and update test cases
@click.option(
    "-u",
    "--update",
    is_flag=True,
    help="Update all stored test cases with newly produced results. "
    "If used with the --add option, this allows the test cases for the added files to "
    "be updated if the file already exists in the test case.",
)
@click.option(
    "-a",
    "--add",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Adds given file to the test case. "
         "(Will first copy file to malware repo if provided.)",
)
@click.option(
    "-i",
    "--add-filelist",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Adds a file of file paths to the test case.",
)
@click.option(
    "-x",
    "--delete",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Deletes given file from the test case. "
         "(Note, this does not delete the file if placed in a malware repo.)",
)
@click.option("-y", "--yes", is_flag=True, help="Auto confirm questions.")
@click.option(
    "-f", "--force", is_flag=True,
    help="Force test case to add/update even when errors are encountered."
)
@click.option(
    "--last-failed", "--lf",
    is_flag=True,
    help="Rerun only the tests that failed at the last run",
)
# Arguments to configure console output
@click.option(
    "--show-passed",
    is_flag=True,
    help="DEPRECATED: Display test case details for passed tests as well."
         "By default only failed tests are shown.",
)
@click.option("-s", "--silent", is_flag=True, help="Limit output to statement saying whether all tests passed or not.")
@click.option(
    "--legacy/--no-legacy",
    default=False,
    show_default=True,
    help="Whether to present json output using legacy schema. "
         "(WARNING: This flag will eventually be removed in favor of only supporting the new schema.)"
)
@click.option(
    "--exit-on-first/--no-exit-on-first",
    default=False,
    show_default=True,
    help="Whether to exit on the first failed test case."
)
@click.option(
    "-c", "--command",
    is_flag=True,
    help="Displays the pytest command that would be run, instead of actually running any test "
         "(only applicable for running tests). "
         "This might be helpful for scripting your own advanced testing apparatus."
)
@click.option(
    "--full-diff",
    is_flag=True,
    help="Whether to display a full diff for failed tests. Disables custom unified diff display."
)
# Parser to process.
@click.argument("parser", nargs=-1, required=False)
def test(
    testcase_dir, malware_repo, nprocs, update, add, add_filelist, delete, yes, force, last_failed, show_passed,
    silent, legacy, exit_on_first, command, full_diff, parser,
):
    """
    Testing utility to create and execute parser test cases.

    \b
    PARSER: Parsers to test. Test all parers if not provided.

    \b
    Common usages::
        mwcp test                                             - Run all tests cases.
        mwcp test foo                                         - Run test cases for foo parser.
        mwcp test foo -u                                      - Update existing test cases for foo parser.
        mwcp test -u                                          - Update existing test cases for all parsers.
        mwcp test --lf                                        - Rerun previously failed test cases.
        mwcp test --lf -u                                     - Update test cases that previously failed.
        mwcp test foo --add=./malware.bin                     - Add test case for malware.bin sample for foo parser.
        mwcp test foo -u --add=./malware.bin                  - Add test case for malware.bin sample.
                                                                Allow updating if a test case for this file already exists.
        mwcp test foo --add-filelist=./paths.txt              - Add tests cases for foo parser using text file of paths.
        mwcp test foo --delete=./malware.bin                  - Delete test case for malware.bin sample for foo parser.
    """
    # Overwrite configuration with command line flags.
    if testcase_dir:
        mwcp.config["TESTCASE_DIR"] = testcase_dir
    if malware_repo:
        mwcp.config["MALWARE_REPO"] = malware_repo

    # Add files listed in filelist to add option.
    if add_filelist:
        # Cast tuple to list so we can manipulate.
        add = list(add)
        for filelist in add_filelist:
            with open(filelist, "r") as f:
                for file_path in f.readlines():
                    add.append(file_path.rstrip("\n"))

    # Add/Delete
    if add or delete:
        click.echo("Adding new test cases. May take a while...")
        if not parser:
            # Don't allow adding a file to ALL test cases.
            raise click.BadParameter("PARSER must be provided when adding or deleting a file from a test case.")

        if legacy:
            tester = Tester(parser_names=parser or [None], nprocs=nprocs)
            for file_path in add:
                if mwcp.config.get("MALWARE_REPO"):
                    file_path = str(testing.add_to_malware_repo(file_path))
                tester.add_test(file_path, force=force, update=update)

            for file_path in delete:
                if mwcp.config.get("MALWARE_REPO"):
                    file_path = str(testing.get_path_in_malware_repo(file_path))
                tester.remove_test(file_path)
        else:
            for file_path in add:
                testing.add_tests(file_path, parsers=parser, force=force, update=update)

            for file_path in delete:
                testing.remove_tests(file_path, parsers=parser)

    # Update
    elif update:
        if not (parser or last_failed) and not yes:
            click.confirm("WARNING: About to update test cases for ALL parsers. Continue?", abort=True)
        click.echo("Updating test cases. May take a while...")
        if legacy:
            if last_failed:
                raise click.BadParameter(f"--last-failed flag is unsupported in legacy mode.")
            tester = Tester(parser_names=parser or [None], nprocs=nprocs)
            tester.update_tests(force=force)
        else:
            if last_failed:
                test_cases = testing.iter_failed_tests()
            else:
                test_cases = testing.iter_test_cases(parsers=parser)
            for test_case in test_cases:
                click.secho(f"Updating {test_case.name}-{test_case.md5}...", fg="green")
                test_case.update(force=force)

    # Run tests
    else:
        if not (parser or last_failed) and not (yes or command):
            click.confirm("PARSER argument not provided. Run tests for ALL parsers?", default=True, abort=True)

        if legacy:
            if last_failed:
                raise click.BadParameter(f"--last-failed flag is unsupported in legacy mode.")
            # Force ERROR level logs so we don't spam the console.
            logging.root.setLevel(logging.ERROR)
            tester = Tester(parser_names=parser or [None], nprocs=nprocs)
            _run_tests(tester, silent, show_passed)

        # Run pytest with "parsers" marker to run parsing tests.
        else:
            # Due to bug in pytest, we won't get our custom command line arguments
            # registered just by using "--pyargs mwcp".
            # Therefore, we need to explicitly define the full path.
            # TODO: Remove this workaround when github.com/pytest-dev/pytest/issues/1596 is solved.
            if testcase_dir:
                testcase_dir = str(pathlib.Path(testcase_dir).resolve())
            if malware_repo:
                malware_repo = str(pathlib.Path(malware_repo).resolve())

            from mwcp.tests import test_parsers

            pytest_args = [
                test_parsers.__file__,
                # TODO: Reenable this when the above the above mentioned issue is fixed.
                # "--pyargs", "mwcp",
                # "-m", "parsers",
                "--disable-pytest-warnings",
                "--durations", "10",
                "--tb", "short",  # Set to short to hide the test_parsers.py code.
                # Set custom cache directory to make it easier to pull it programmatically later.
                "-o", f"cache_dir={mwcp.config.pytest_cache_dir}",
            ]
            if full_diff:
                pytest_args += ["--full-diff"]
            if not silent:
                pytest_args += ["-vv"]

            if last_failed:
                # Run last failed or none if no previous failures.
                pytest_args += ["--lf", "--lfnf", "none"]
            else:
                # Reset cache for keeping track of previously failed tests.
                pytest_args += ["--cache-clear"]

            if parser:
                pytest_args += ["-k", " or ".join(parser)]

            if nprocs != 1:
                pytest_args += ["-n", str(nprocs) if nprocs else "auto"]
            if testcase_dir:
                pytest_args += ["--testcase-dir", testcase_dir]
            if malware_repo:
                pytest_args += ["--malware-repo", malware_repo]
            if exit_on_first:
                pytest_args += ["-x"]

            logger.debug(f"Running pytest with arguments: {pytest_args}")
            if command:
                print(" ".join(map(shlex.quote, ["pytest"] + pytest_args)))
            else:
                status = pytest.main(pytest_args)
                sys.exit(status)


@main.command()
def schema():
    """
    Displays JSON Schema for a single report in JSON.
    NOTE: This is the schema for a single report. Depending on how you use MWCP,
    you may get a list of these reports instead.
    """
    print(json.dumps(mwcp.schema(), indent=4))


@main.command()
@click.option(
    "-o",
    "--output-dir",
    default=".",
    type=click.Path(exists=True, file_okay=False, path_type=pathlib.Path),
    help="Root output directory to store downloaded files. (defaults to current directory)",
)
@click.option(
    "--last-failed", "--lf",
    is_flag=True,
    help="Download samples for tests that previously failed.",
)
@click.argument("md5_or_parser", nargs=-1, required=False)
def download(md5_or_parser: Tuple[str], output_dir, last_failed):
    """
    Downloads file from malware repo into current directory.

    \b
    MD5_OR_PARSER: One or more md5 hashes or parser names of the samples to download. (Hashes may be partial)
        For parser names, all the samples for that parser test will be downloaded.

    \b
    Common usages::
        mwcp download foo          - Download test samples for foo parser
        mwcp download abcdef       - Download sample with md5 hash starting with 'abcdef'
        mwcp download --lf         - Download samples from previously failed tests.
    """
    md5s = []
    for entry in md5_or_parser:
        md5s.extend(list(testing.iter_md5s(entry)) or [entry])
    if last_failed:
        for test_case in testing.iter_failed_tests():
            md5s.append(test_case.md5)

    for md5 in md5s:
        try:
            file_path = testing.download(md5, output_dir=output_dir)
            click.secho(f"Downloaded: {file_path}")
        except IOError as e:
            click.secho(str(e), err=True, fg="red")
            continue


if __name__ == "__main__":
    main(sys.argv[1:])
