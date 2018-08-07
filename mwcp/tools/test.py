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
# pkg_resources is optional, to keep backwards compatibility.
import timeit

try:
    import pkg_resources
except ImportError:
    pkg_resources = None

import mwcp

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
                             "(defaults to a 'parsertests' directory located in the root of the "
                             "parser's home module)")
    parser.add_argument("--parserdir",
                        metavar="DIR",
                        default=None,
                        dest="parserdir",
                        help="Parsers directory")

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
                        help="Level of log messages to display. 1 for INFO, 2 for DEBUG")

    return parser


def main():
    """Run tool."""

    print('')

    # Get command line arguments
    argparser = get_arg_parser()
    args, input_files = argparser.parse_known_args()

    # Setup logging
    mwcp.setup_logging()
    logging.root.setLevel(logging.WARNING - (args.verbose * 10))

    if args.all_tests or not args.parser_name:
        parsers = [None]
    else:
        parsers = [args.parser_name]

    # Configure reporter based on args
    reporter = mwcp.Reporter(disableoutputfiles=True, parserdir=args.parserdir)

    # Configure test object
    tester = Tester(
        reporter=reporter, results_dir=args.test_case_dir)

    # Gather all our input files
    if args.input_file:
        input_files = read_input_list(input_files[0])

    # Run test cases
    if args.run_tests:
        print("Running test cases. May take a while...")

        start_time = timeit.default_timer()
        test_infos = []
        test_results = []
        # json_list = []
        all_passed = True

        test_iter = tester.run_tests(
            parsers,
            list(filter(None, args.field_names.split(","))),
            ignore_field_names=list(filter(None, args.exclude_field_names.split(","))),
            nprocs=args.nprocs
        )

        for test_result, test_info in test_iter:
            test_infos.append(test_info)
            test_results.append(test_result)
            all_passed &= test_result.passed

            if not args.silent:
                # Skip print() to immediately flush stdout buffer (issue in Docker containers)
                sys.stdout.write(
                    "{finished}/{total} - {parser} {filename} {run_time:.4f}s\n".format(**test_info)
                )
                sys.stdout.flush()
                if args.only_failed_tests:
                    tester.print_test_results(
                        test_results,
                        failed_tests=True,
                        passed_tests=False,
                        json_format=args.json)
                else:
                    tester.print_test_results(
                        test_results,
                        failed_tests=True,
                        passed_tests=True,
                        json_format=args.json)

        end_time = timeit.default_timer()

        # Avoid a ZeroDivisionError.
        if not test_infos:
            return

        if not args.silent:
            print('\nTest stats:')
            print('\nTop 10 Slowest Test Cases:')
            # Cases sorted slowest first
            sorted_cases = sorted(test_infos, key=lambda x: x['run_time'], reverse=True)
            for i, info in enumerate(sorted_cases[:10]):
                print('{:2}. {} {} {:.4f}s'.format(i + 1, info['parser'], info['filename'], info['run_time']))

            print('\nTop 10 Fastest Test Cases:')
            for i, info in enumerate(list(reversed(sorted_cases))[:10]):
                print('{:2}. {} {} {:.4f}s'.format(i + 1, info['parser'], info['filename'], info['run_time']))

            run_times = [info['run_time'] for info in test_infos]
            print('\nMean Running Time: {:.4f}s'.format(
                sum(run_times) / len(test_infos)
            ))
            print('Median Running Time: {:.4f}s'.format(
                _median(run_times)
            ))
            print('Cumulative Running Time: {}'.format(datetime.timedelta(seconds=sum(run_times))))
            print()

        print("Total Running Time: {}".format(datetime.timedelta(seconds=end_time - start_time)))
        print("All Passed = {0}\n".format(all_passed))
        exit(0 if all_passed else 1)

    # Delete files from test cases
    elif args.delete:
        removed_files = tester.remove_test_results(
            args.parser_name, input_files)
        for filename in removed_files:
            print(u"Removing results for {} in {}".format(
                filename, tester.get_results_filepath(args.parser_name)))

    # Update previously existing test cases
    elif args.update and args.parser_name:
        logging.root.setLevel(logging.INFO)  # Force info level logs so test cases stay consistent.
        print("Updating test cases. May take a while...")
        results_file_path = tester.get_results_filepath(args.parser_name)
        if os.path.isfile(results_file_path):
            input_files = tester.list_test_files(args.parser_name)
        else:
            print("No test case file found for parser '{}'. No update could be made.".format(args.parser_name))
            return

        for input_file in input_files:
            metadata = tester.gen_results(
                parser_name=args.parser_name, input_file_path=input_file)
            if len(metadata) > 1 and len(reporter.errors) == 0:
                print(u"Updating results for {} in {}".format(input_file, results_file_path))
                tester.update_test_results(results_file_path=results_file_path,
                                           results_data=metadata,
                                           replace=True)
            elif len(metadata) > 1 and len(reporter.errors) > 0:
                print(u"Error occurred for {} in {}, not updating".format(input_file, results_file_path))
                print('\n'.join(reporter.errors))
            else:
                print(u"Empty results for {} in {}, not updating".format(input_file, results_file_path))

    # Add/update test cases for specified input files and specified parser
    elif args.parser_name and not args.delete and input_files:
        logging.root.setLevel(logging.INFO)  # Force info level logs so test cases stay consistent.
        results_file_path = tester.get_results_filepath(args.parser_name)
        for input_file in input_files:
            metadata = tester.gen_results(
                parser_name=args.parser_name, input_file_path=input_file)
            if len(metadata) > 1 and len(reporter.errors) == 0:
                print(u"Updating results for {} in {}".format(input_file, results_file_path))
                tester.update_test_results(results_file_path=results_file_path,
                                           results_data=metadata,
                                           replace=True)
            elif len(metadata) > 1 and len(reporter.errors) > 0:
                print(u"Error occurred for {} in {}, not updating".format(input_file, results_file_path))
            else:
                print(u"Empty results for {} in {}, not updating".format(input_file, results_file_path))
    else:
        argparser.print_help()


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
