"""
DC3-MWCP Framework command line tool.

Used for running and testing parsers.
"""

from __future__ import print_function, division
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
from mwcp.tester import Tester
from mwcp.utils.stringutils import convert_to_unicode


logger = logging.getLogger('mwcp')



@click.group(context_settings={'help_option_names': ['-h', '--help']})
@click.option('-d', '--debug', is_flag=True, help="Enables DEBUG level logs.")
@click.option('-v', '--verbose', is_flag=True, help="Enables INFO level logs.")
@click.option('-c', '--config', 'config_path', type=click.Path(exists=True, dir_okay=False),
              help='File path to configuration file.', default=mwcp.config.user_path, show_default=True,
              envvar='MWCP_CONFIG', show_envvar=True)
@click.option('--parser-dir', type=click.Path(exists=True, file_okay=False),
              help="Optional extra parser directory.",
              envvar='MWCP_PARSER_DIR')
@click.option('--parser-config', type=click.Path(exists=True, dir_okay=False),
              help="Optional parser configuration file to use with extra parser directory.",
              envvar='MWCP_PARSER_CONFIG')
@click.option('--parser-source',
              help="Set a default parsers source to use. If not provided parsers from all sources will be available.",
              envvar='MWCP_PARSER_SOURCE')
def main(debug, verbose, config_path, parser_dir, parser_config, parser_source):
    if (parser_dir and parser_dir == os.getenv('MWCP_PARSER_DIR')) \
            or (parser_config and parser_config == os.getenv('MWCP_PARSER_CONFIG')) \
            or (parser_source and parser_source == os.getenv('MWCP_PARSER_SOURCE')):
        warnings.warn(
            'Setting parser directory, parser config or parser source'
            ' through an environment variable is deprecated. '
            'Please set these values in the configuration file or in the command line.')

    # Setup configuration
    mwcp.config.load(config_path)
    if parser_dir:
        mwcp.config['PARSER_DIR'] = parser_dir
    parser_dir = mwcp.config.get('PARSER_DIR')
    if parser_config:
        mwcp.config['PARSER_CONFIG_PATH'] = parser_config
    parser_config = mwcp.config.get('PARSER_CONFIG_PATH')
    if parser_source:
        mwcp.config['PARSER_SOURCE'] = parser_source
    parser_source = mwcp.config.get('PARSER_SOURCE')

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
@click.option('--host', default='127.0.0.1', show_default=True, help="The interface to bind to.")
@click.option('--port', default=8080, show_default=True, help="The port to bind to.")
@click.option(
    '--debug', is_flag=True,
    help="Show the interactive debugger if errors occur.")
def serve(host, port, debug):
    """Run a server to handle parsing requests."""
    from mwcp.tools import server

    if debug:
        os.environ['FLASK_ENV'] = 'development'

    app = server.create_app()
    app.run(host=host, port=port, debug=debug, use_reloader=False)


@main.command()
def config():
    """Opens up configuration file for editing."""
    file_path = mwcp.config.user_path
    if sys.platform == 'win32':
        try:
            os.startfile(file_path, 'edit')
        except WindowsError:
            os.startfile(file_path)
    else:
        opener = 'open' if sys.platform == 'darwin' else 'xdg-open'
        subprocess.call([opener, file_path])

    # TODO: Add a "-u" flag to this command when we need to update the user's configuration file
    # with new fields.


@main.command('list')
@click.option('-a', '--all', 'all_', is_flag=True,
              help="Whether to also include parsers not listed in any parsers configuration file.")
@click.option('-j', '--json', 'json_', is_flag=True, help="Display as JSON output.")
def list_(all_, json_):
    """Lists registered malware config parsers."""
    descriptions = mwcp.get_parser_descriptions(config_only=not all_)
    if json_:
        print(json.dumps(descriptions, indent=4))
    else:
        print(tabulate.tabulate(descriptions, headers=['NAME', 'SOURCE', 'AUTHOR', 'DESCRIPTION']))


# Column order for standard fields in csv.
# (All other fields will be appended in alphabetical order after these)
_STD_CSV_COLUMNS = [
    'scan_date', 'inputfilename', 'outputfile.name', 'outputfile.description',
    'outputfile.md5', 'outputfile.base64'
]


def _format_metadata_value(v):
    """Formats metadata value to a human readable unicode string."""
    if isinstance(v, (list, tuple)):
        result = u''
        for j in v:
            if not isinstance(j, (bytes, str)):
                result += u'{}\n'.format(u', '.join(map(convert_to_unicode, j)))
            else:
                result += u'{}\n'.format(convert_to_unicode(j))
        return result.rstrip()
    elif isinstance(v, dict):
        result = u''
        for field, value in six.iteritems(v):
            if isinstance(value, (list, tuple)):
                value = u'[{}]'.format(u', '.join(value))

            result += u'{}: {}\n'.format(field, value)
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
    scan_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Add/Teak metadata.
    for inputfilename, metadata in zip(input_files, results):
        # Add scan date.
        metadata[u'scan_date'] = scan_date
        if u'inputfilename' not in metadata:
            metadata[u'inputfilename'] = inputfilename

        # Flatten 'other' entry so nested values get their own columns,
        # are more readable, and easier to individually analyze.
        #
        # Example:
        #   {'other': {"unique_entry": "value", "unique_key": "value2"}}
        #   Results in columns: other, other.unique_entry, other.unique_key
        if u'other' in metadata:
            for sub_key, sub_value in metadata[u'other'].items():
                metadata[u'other.{}'.format(convert_to_unicode(sub_key))] = sub_value
            del metadata[u'other']

        # Split outputfile into multiple fields.
        if u'outputfile' in metadata:
            value = list(zip(*metadata[u'outputfile']))
            metadata[u'outputfile.name'] = value[0]
            metadata[u'outputfile.description'] = value[1]
            metadata[u'outputfile.md5'] = value[2]
            del metadata[u'outputfile']

    # Sort columns, but with PREFIX_COLUMNS showing up first.
    column_names = set(itertools.chain(*(metadata.keys() for metadata in results)))
    column_names = sorted(
        column_names, key=lambda x: str(_STD_CSV_COLUMNS.index(x)) if x in _STD_CSV_COLUMNS else str(x))

    # Reformat metadata and write to CSV
    if csv_path is None:
        csvfile = sys.stdout
    else:
        csvfile = open(csv_path, 'wb' if six.PY2 else 'w')

    try:
        dw = csv.DictWriter(csvfile, fieldnames=column_names, lineterminator='\n')
        dw.writeheader()
        for metadata in results:
            dw.writerow({k: _format_metadata_value(v) for k, v in metadata.items()})
    finally:
        if csv_path:
            csvfile.close()


def _parse_file(reporter, file_path, parser, include_filename=False):
    """
    Parses given file_path with given parser.

    :param reporter: Reporter to use for parsing.
    :param file_path: File path to parse or "-" for stdin
    :param parser: Name of parser to run (can use ":" notation)
    :param include_filename: Whether to include input file metadata in the results.
    :return: Dictionary of results.
    """
    if file_path == "-":
        reporter.run_parser(parser, data=sys.stdin.read())
    else:
        reporter.run_parser(parser, file_path)

    result = reporter.metadata
    input_file = reporter.input_file

    # TODO: This should just be included by the reporter by default.
    if include_filename:
        result['inputfilename'] = file_path
        result['md5'] = input_file.md5
        result['sha1'] = input_file.sha1
        result['sha256'] = input_file.sha256
        result['parser'] = parser
        if input_file.pe:
            result['compiletime'] = datetime.datetime.fromtimestamp(
                reporter.input_file.pe.FILE_HEADER.TimeDateStamp).isoformat()

    if reporter.errors:
        result["errors"] = reporter.errors

    return result


@main.command()
@click.option('-f', '--format', type=click.Choice(['csv', 'json']),
              help='Displays results in another format.')
@click.option('-o', '--output-dir', type=click.Path(exists=True, file_okay=False),
              help='Root output directory to store residual files. (defaults to current directory)')
@click.option('--output-files/--no-output-files', default=True, show_default=True,
              help='Whether to output files to filesystem.')
@click.option('--cleanup/--no-cleanup', default=True, show_default=True,
              help='Whether to cleanup temporary files after parsing.')
@click.option('-i', '--include-filename', is_flag=True,
              help="Include file information such as filename, hashes, and compile time in parser output.")
@click.argument('parser', required=True)
@click.argument('input', nargs=-1, type=click.Path())
def parse(parser, input, format, output_dir, output_files, cleanup, include_filename):
    """
    Parses given input with given parser.

    \b
    PARSER: Name of parser to run.
    INPUT: One or more input file paths. (Wildcards are allowed).

    \b
    Common usages::
        mwcp parse foo ./malware.bin                          - Run foo parser on ./malware.bin
        mwcp parse foo ./repo/*                               - Run foo parser on files found in repo directory.
        mwcp parse -f json foo ./malware.bin                  - Run foo parser and display results as json.
        mwcp parse -f csv foo ./repo/* > ./results.csv        - Run foo parser on a directory and output results as a csv file.
    """
    # Python won't process wildcards when used through Windows command prompt.
    if any('*' in path for path in input):
        new_input = []
        for path in input:
            if '*' in path:
                new_input.extend(glob.glob(path))
            else:
                new_input.append(path)
        input = new_input

    input_files = list(filter(os.path.isfile, input))
    output_dir = output_dir or ''

    # Run MWCP
    try:
        results = []
        for path in input_files:
            reporter = mwcp.Reporter(
                # Store output files to a folder with the same name as the input file.
                outputdir=os.path.join(output_dir, os.path.basename(path) + '_mwcp_output'),
                disable_output_files=not output_files,
                disable_temp_cleanup=not cleanup)
            logger.info('Parsing: {}'.format(path))
            result = _parse_file(reporter, path, parser, include_filename=include_filename)
            results.append(result)
            if not format:
                reporter.print_report()

        if format == 'csv':
            _write_csv(input_files, results)
        elif format == 'json':
            print(json.dumps(results, indent=4))

    except Exception as e:
        error_message = "Error running DC3-MWCP: {}".format(e)
        traceback.print_exc()
        if format == 'json':
            print(json.dumps({'errors': [error_message]}))
        else:
            print(error_message)
        sys.exit(1)


def _get_malware_repo_path(file_path):
    """
    Gets file path for a file in the malware_repo based on the md5 of the given file_path.
    """
    if not mwcp.config.get('MALWARE_REPO'):
        raise ValueError('Malware Repository not set.')
    with open(file_path, 'rb') as fo:
        md5 = hashlib.md5(fo.read()).hexdigest()
    return os.path.join(mwcp.config['MALWARE_REPO'], md5[0:4], md5)


def _add_to_malware_repo(file_path):
    """
    Adds the given file path to the malware repo.
    Returns resulting destination path.
    """
    dest_path = _get_malware_repo_path(file_path)
    dest_dir = os.path.dirname(dest_path)

    if os.path.isfile(dest_path):
        click.echo('File already exists in malware repo: {}'.format(dest_path))
        return dest_path

    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    click.echo('Copying {} to {}'.format(file_path, dest_path))
    shutil.copy(file_path, dest_path)
    return dest_path


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
        raise ValueError('No median for empty data.')
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
                run_time=test_result.run_time
            )
            # Skip print() to immediately flush stdout buffer (issue in Docker containers)
            sys.stdout.write(message + '\n')
            sys.stdout.flush()
            test_result.print(failed_tests=True, passed_tests=show_passed)

    end_time = timeit.default_timer()

    # Present test statistics
    if not silent and test_results:
        print('\nTest stats:')
        print('\nTop 10 Slowest Test Cases:')

        format_str = "{index:2}. " + msg_format

        # Cases sorted slowest first
        sorted_cases = sorted(test_results, key=lambda x: x.run_time, reverse=True)
        for i, test_result in enumerate(sorted_cases[:10], start=1):
            print(format_str.format(
                index=i,
                parser=test_result.parser,
                filename=test_result.filename,
                run_time=test_result.run_time
            ))

        print('\nTop 10 Fastest Test Cases:')
        for i, test_result in enumerate(list(reversed(sorted_cases))[:10], start=1):
            print(format_str.format(
                index=i,
                parser=test_result.parser,
                filename=test_result.filename,
                run_time=test_result.run_time
            ))

        run_times = [test_result.run_time for test_result in test_results]
        print('\nMean Running Time: {:.4f}s'.format(
            sum(run_times) / len(test_results)
        ))
        print('Median Running Time: {:.4f}s'.format(
            _median(run_times)
        ))
        print('Cumulative Running Time: {}'.format(datetime.timedelta(seconds=sum(run_times))))
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
@click.option('-t', '--testcase-dir', type=click.Path(exists=True, file_okay=False),
              help='Directory containing JSON test case files. (defaults to a '
                   '"tests" directory located within the root of the parsers directory)',
              envvar='MWCP_TESTCASE_DIR')
@click.option('-m', '--malware-repo', type=click.Path(exists=True, file_okay=False),
              help='Directory containing malware samples used for testing.',
              envvar='MWCP_MALWARE_REPO')
# Arguments used for run test cases.
@click.option('-n', '--nprocs', type=int,
              help='Number of test cases to run simultaneously. [default: 3/4 * logical CPU cores]')
# Arguments used to generate and update test cases
@click.option('-u', '--update', is_flag=True,
              help='Update all stored test cases with newly produced results. '
                   'If used with the --add option, this allows the test cases for the added files to '
                   'be updated if the file already exists in the test case.')
@click.option('-a', '--add', multiple=True, type=click.Path(exists=True, dir_okay=False),
              help='Adds given file to the test case. (Will first copy file to malware repo if provided.)')
@click.option('-i', '--add-filelist', multiple=True, type=click.Path(exists=True, dir_okay=False),
              help='Adds a file of file paths to the test case.')
@click.option('-x', '--delete', multiple=True, type=click.Path(exists=True, dir_okay=False),
              help='Deletes given file from the test case. '
                   '(Note, this does not delete the file if placed in a malware repo.)')
@click.option('-y', '--yes', is_flag=True, help="Auto confirm questions.")
@click.option('--force', is_flag=True, help="Force test case add/update when errors are encountered.")
# Arguments to configure console output
@click.option('-f', '--show-passed', is_flag=True,
              help='Display tests case details for passed tests as well.'
                   'By default only failed tests are shown.')
@click.option('-s', '--silent', is_flag=True,
              help='Limit output to statemtn saying whether all tests passed or not.')
# Parser to process.
@click.argument('parser', nargs=-1, required=False)
def test(testcase_dir, malware_repo, nprocs, update, add, add_filelist, delete,
         yes, force, show_passed, silent, parser):
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
        mwcp test foo --add=./malware.bin                     - Add test case for malware.bin sample for foo parser.
        mwcp test foo -u --add=./malware.bin                  - Add test case for malware.bin sample.
                                                                Allow updating if a test case for this file already exists.
        mwcp test foo --add-filelist=./paths.txt              - Add tests cases for foo parser using text file of paths.
        mwcp test foo --delete=./malware.bin                  - Delete test case for malware.bin sample for foo parser.
    """
    if (testcase_dir and testcase_dir == os.getenv('MWCP_TESTCASE_DIR')) \
            or (malware_repo and malware_repo == os.getenv('MWCP_MALWARE_REPO')):
        warnings.warn(
            'Setting testcase directory or malware repo through an environment variable is deprecated. '
            'Please set these values in the configuration file or in the command line.')
    # Overwrite configuration with command line flags.
    if testcase_dir:
        mwcp.config['TESTCASE_DIR'] = testcase_dir
    if malware_repo:
        mwcp.config['MALWARE_REPO'] = malware_repo

    # Configure test object
    reporter = mwcp.Reporter(disable_output_files=True)
    tester = Tester(
        reporter=reporter,
        parser_names=parser or [None],
        nprocs=nprocs,
    )

    # Add/Delete
    if add or add_filelist or delete:
        click.echo('Adding new test cases. May take a while...')
        if not parser:
            # Don't allow adding a file to ALL test cases.
            raise click.BadParameter('PARSER must be provided when adding or deleting a file from a test case.')

        # Cast tuple to list so we can manipulate.
        add = list(add)
        for filelist in add_filelist:
            with open(filelist, 'r') as f:
                for file_path in f.readlines():
                    add.append(file_path.rstrip('\n'))

        for file_path in add:
            if mwcp.config.get('MALWARE_REPO'):
                file_path = _add_to_malware_repo(file_path)
            tester.add_test(file_path, force=force, update=update)

        for file_path in delete:
            if mwcp.config.get('MALWARE_REPO'):
                file_path = _get_malware_repo_path(file_path)
            tester.remove_test(file_path)

    # Update
    elif update:
        if not parser and not yes:
            click.confirm('WARNING: About to update test cases for ALL parsers. Continue?', abort=True)
        click.echo('Updating test cases. May take a while...')
        tester.update_tests(force=force)

    # Run tests
    else:
        if not parser and not yes:
            click.confirm('PARSER argument not provided. Run tests for ALL parsers?', default=True, abort=True)
        # Force ERROR level logs so we don't spam the console.
        logging.root.setLevel(logging.ERROR)
        _run_tests(tester, silent, show_passed)


if __name__ == '__main__':
    main(sys.argv[1:])
