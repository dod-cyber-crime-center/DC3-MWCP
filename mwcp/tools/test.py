#!/usr/bin/env python

"""
DC3-MWCP Framework test case tool
"""
from __future__ import print_function, division

# Standard imports
import argparse
import datetime
import logging
import os
import sys
import timeit
import warnings

# pkg_resources is optional, to keep backwards compatibility.
import timeit

try:
    import pkg_resources
except ImportError:
    pkg_resources = None

import mwcp
import mwcp.parsers

from mwcp.tester import DEFAULT_EXCLUDE_FIELDS
# DC3-MWCP framework imports
from mwcp.tester import Tester


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


def get_arg_parser():
    """Define command line arguments and return argument parser."""

    description = '''DC3-MWCP Framework: testing utility to create test cases and execute them.

Common usages:

$ mwcp-test -ta                                 Run all test cases and only show failed cases
$ mwcp-test -p parser -tf                       Run test cases for single parser and show successful tests
$ mwcp-test -p parser -u                        Update existing test cases for a parser
$ mwcp-test -ua                                 Update existing test cases for all parsers
$ mwcp-test -p parser -i file_paths_file        Add new test cases for a parser
$ mwcp-test -p parser -i file_paths_file -d     Delete test cases for a parser
'''
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     usage='%(prog)s -p parser [options] [input files]')

    # Required arguments
    parser.add_argument("-o", "--testcasedir",
                        default=None,
                        type=str,
                        dest="test_case_dir",
                        help="Directory containing JSON test case files. "
                             "(defaults to a 'tests' directory located within the root of the "
                             "parsers directory)")
    parser.add_argument("--parserdir",
                        metavar="DIR",
                        default=None,
                        dest="parserdir",
                        help="Parsers directory")
    parser.add_argument("--parserconfig",
                        metavar="FILE",
                        default=None,
                        dest="parserconfig",
                        help="Parsers configuration file (must be provided if using parserdir)")
    parser.add_argument("--parsersource",
                        metavar="SOURCE_NAME",
                        default=None,
                        dest="parsersource",
                        help="Set a default parser source to use. "
                             "If not provided parsers from all sources will be available.")

    # Arguments used to run test cases
    parser.add_argument("-t",
                        default=False,
                        dest="run_tests",
                        action="store_true",
                        help="Run test cases. Optional filters can be given using '-p' and/or '-k' arguments.")
    parser.add_argument("-p",
                        type=str,
                        dest="parser_name",
                        default="",
                        help="parser (use ':' notation to specify source if necessary e.g. 'mwcp-acme:Foo')")
    parser.add_argument("-k",
                        type=str,
                        dest="field_names",
                        default="",
                        help="Fields (csv) to compare results for. Reference 'fields.json'. " +
                             "Ex. socketaddress,registrykey")
    parser.add_argument("-x",
                        type=str,
                        dest="exclude_field_names",
                        default=",".join(DEFAULT_EXCLUDE_FIELDS),
                        help="Fields (csv) excluded from test cases/comparisons. default: %(default)s")
    parser.add_argument("-a",
                        default=False,
                        dest="all_tests",
                        action="store_true",
                        help="select all available parsers, used with -t to test all parsers")
    parser.add_argument("-n",
                        type=int,
                        dest="nprocs",
                        default=None,
                        help="Number of test cases to run simultaneously. Default: 3/4 * logical CPU cores.")

    # Arguments used to generate and update test cases
    parser.add_argument("-i",
                        dest="input_file",
                        action="store_true",
                        default=False,
                        help="single input file provides a list of files to use as input, one per line")
    parser.add_argument("-u",
                        default=False,
                        dest="update",
                        action="store_true",
                        help="Update all stored test cases with newly produced results.")
    parser.add_argument("-d",
                        default=False,
                        dest="delete",
                        action="store_true",
                        help="delete file(s) from test cases")

    # Arguments to configure console output
    parser.add_argument("-f",
                        default=True,
                        action="store_false",
                        dest="only_failed_tests",
                        help="Display all test case details. By default, only failed tests are shown.")
    parser.add_argument("-j",
                        default=False,
                        action="store_true",
                        dest="json",
                        help="JSON formatted output.")
    parser.add_argument("-s",
                        default=False,
                        action="store_true",
                        dest="silent",
                        help="Limit output to statement saying whether all tests passed or not.")
    parser.add_argument("-v", "--verbose",
                        default=0,
                        action="count",
                        dest="verbose",
                        help="Level of log messages to display. 1 for WARNING, 2 for INFO, 3 for DEBUG")

    return parser


def main():
    """Run tool."""

    warnings.warn("WARNING: mwcp-test is deprecated. Please use \"mwcp test\" instead.")

    print('')

    # Get command line arguments
    argparser = get_arg_parser()
    args, input_files = argparser.parse_known_args()

    # Setup logging
    mwcp.setup_logging()
    logging.root.setLevel(logging.ERROR - (args.verbose * 10))

    if args.all_tests or not args.parser_name:
        parsers = [None]
    else:
        parsers = [args.parser_name]

    if args.parserdir and args.parserconfig:
        mwcp.register_parser_directory(args.parserdir, args.parserconfig)
    elif args.parserdir or args.parserconfig:
        raise ValueError('Both --parserdir and --parserconfig must be specified.')
    else:
        mwcp.register_entry_points()

    if args.parsersource:
        mwcp.set_default_source(args.parsersource)

    # Configure reporter based on args
    reporter = mwcp.Reporter(disable_output_files=True)

    # Configure test object
    tester = Tester(
        reporter=reporter, results_dir=args.test_case_dir, parser_names=parsers, nprocs=args.nprocs,
        field_names=filter(None, args.field_names.split(",")),
        ignore_field_names=filter(None, args.exclude_field_names.split(","))
    )

    # Gather all our input files
    if args.input_file:
        input_files = read_input_list(input_files[0])

    # Delete files from test cases
    if args.delete:
        for file_path in input_files:
            tester.remove_test(file_path)

    # Update previously existing test cases
    elif args.update and args.parser_name:
        print("Updating test cases. May take a while...")
        tester.update_tests()

    # Add/update test cases for specified input files and specified parser
    elif args.parser_name and not args.delete and input_files:
        for file_path in input_files:
            tester.add_test(file_path)

    # Run test cases
    else:
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
            parser_len = max(len(test_case.parser_name) for test_case in tester.test_cases)
            filename_len = max(len(test_case.filename) for test_case in tester.test_cases)
        msg_format = "{{parser:{0}}} {{filename:{1}}} {{run_time:.4f}}s".format(parser_len, filename_len)

        format_str = "{{count:> {0}d}}/{{total:0{0}d}} - ".format(digits) + msg_format

        # Run tests and output progress results.
        for count, test_result in enumerate(tester, start=1):
            all_passed &= test_result.passed
            if not test_result.passed:
                failed.append((count, test_result.parser_name, test_result.filename))

            if test_result.run_time:  # Ignore missing tests from stat summary.
                test_results.append(test_result)

            if not args.silent:
                message = format_str.format(
                    count=count,
                    total=total,
                    parser=test_result.parser_name,
                    filename=test_result.filename,
                    run_time=test_result.run_time
                )
                # Skip print() to immediately flush stdout buffer (issue in Docker containers)
                sys.stdout.write(message + '\n')
                sys.stdout.flush()
                test_result.print(
                    failed_tests=True, passed_tests=not args.only_failed_tests, json_format=args.json
                )

        end_time = timeit.default_timer()

        # Present test statistics
        if not args.silent and test_results:
            print('\nTest stats:')
            print('\nTop 10 Slowest Test Cases:')

            format_str = "{index:2}. " + msg_format

            # Cases sorted slowest first
            sorted_cases = sorted(test_results, key=lambda x: x.run_time, reverse=True)
            for i, test_result in enumerate(sorted_cases[:10], start=1):
                print(format_str.format(
                    index=i,
                    parser=test_result.parser_name,
                    filename=test_result.filename,
                    run_time=test_result.run_time
                ))

            print('\nTop 10 Fastest Test Cases:')
            for i, test_result in enumerate(list(reversed(sorted_cases))[:10], start=1):
                print(format_str.format(
                    index=i,
                    parser=test_result.parser_name,
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


def read_input_list(filename):
    inputfilelist = []
    if filename:
        if filename == "-":
            inputfilelist = [line.rstrip() for line in sys.stdin]
        else:
            with open(filename, "rb") as f:
                inputfilelist = [line.rstrip() for line in f]

    return inputfilelist


if __name__ == "__main__":
    main()
