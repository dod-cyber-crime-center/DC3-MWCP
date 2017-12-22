#!/usr/bin/env python

"""
DC3-MWCP Framework test case tool
"""
from __future__ import print_function

# Standard imports
import argparse
import os
import sys

import mwcp

from mwcp.tester import DEFAULT_EXCLUDE_FIELDS
# DC3-MWCP framework imports
from mwcp.tester import Tester


def get_arg_parser(mwcproot):
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
    parser.add_argument("-o",
                        default=os.path.join(mwcproot, "mwcp", "parsertests"),
                        type=str,
                        dest="test_case_dir",
                        help="Directory containing JSON test case files.")

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

    return parser


def main():
    """Run tool."""

    print('')

    # Setup
    mwcproot = ""
    if os.path.dirname(sys.argv[0]):
        mwcproot = os.path.dirname(sys.argv[0])

    # Get command line arguments
    argparser = get_arg_parser(mwcproot)
    args, input_files = argparser.parse_known_args()

    # Configure reporter based on args
    reporter = mwcp.Reporter(disableoutputfiles=True)

    # Configure test object
    tester = Tester(
        reporter=reporter, results_dir=args.test_case_dir)

    parser_descriptions = mwcp.get_parser_descriptions()
    valid_parser_names = [x[0] for x in parser_descriptions]

    parsers = []
    if args.parser_name:
        if args.parser_name in valid_parser_names:
            parsers = [args.parser_name]
        else:
            print("Error: Invalid parser name(s) specified. Parser names are case sensitive.")
            sys.exit(1)
    if args.all_tests:
        parsers = valid_parser_names

    if not parsers:
        print("You must specify a single parser or all parsers to run or update.")
        sys.exit(2)

    results_file_path = tester.get_results_filepath(args.parser_name)

    # Gather all our input files
    if args.input_file:
        input_files = read_input_list(input_files[0])

    # Run test cases
    if args.run_tests:
        print("Running test cases. May take a while...")

        # Run tests
        test_results = tester.run_tests(parsers, list(filter(None, args.field_names.split(","))),
                                        ignore_field_names=list(filter(None, args.exclude_field_names.split(","))))

        # Determine if any test cases failed
        all_passed = True
        if any([not test_result.passed for test_result in test_results]):
            all_passed = False
        print("All Passed = {0}\n".format(all_passed))

        if not args.silent:
            if args.only_failed_tests:
                tester.print_test_results(test_results,
                                          failed_tests=True,
                                          passed_tests=False,
                                          json_format=args.json)
            else:
                tester.print_test_results(test_results,
                                          failed_tests=True,
                                          passed_tests=True,
                                          json_format=args.json)
        if all_passed:
            sys.exit(0)
        else:
            sys.exit(1)

    # Delete files from test cases
    elif args.delete:
        removed_files = tester.remove_test_results(
            args.parser_name, input_files)
        for filename in removed_files:
            print(u"Removing results for {} in {}".format(filename, results_file_path))

    # Update previously existing test cases
    elif args.update:
        print("Updating test cases. May take a while...")
        for parser in parsers:
            results_file_path = tester.get_results_filepath(parser)
            if os.path.isfile(results_file_path):
                input_files = tester.list_test_files(parser)
            else:
                print("No test case file found for parser '{}'. No update could be made.".format(parser))
                continue

            for input_file in input_files:
                metadata = tester.gen_results(
                    parser_name=parser, input_file_path=input_file)
                if len(metadata) > 1 and len(reporter.errors) == 0:
                    print(u"Updating results for {} in {}".format(input_file, results_file_path))
                    tester.update_test_results(results_file_path=results_file_path,
                                               results_data=metadata,
                                               replace=True)
                elif len(metadata) > 1 and len(reporter.errors) > 0:
                    print(u"Error occurred for {} in {}, not updating".format(input_file, results_file_path))
                else:
                    print(u"Empty results for {} in {}, not updating".format(input_file, results_file_path))

    # Add/update test cases for specified input files and specified parser
    elif args.parser_name and (not args.delete and input_files):
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
