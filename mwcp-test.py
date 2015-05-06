#!/usr/bin/env python
'''
DC3-MWCP Framework test case tool
'''

# Standard imports
import argparse
import os
import sys

# DC3-MWCP framework imports
from mwcp.malwareconfigtester import malwareconfigtester
from mwcp.malwareconfigreporter import malwareconfigreporter
from mwcp.malwareconfigtester import DEFAULT_EXCLUDE_FIELDS

def get_arg_parser(mwcproot):
    ''' Define command line arguments and return argument parser. '''
    
    description = "DC3-MWCP Framework: testing utility to create test cases and execute them"
    parser = argparse.ArgumentParser(description = description,
                                     formatter_class = argparse.RawDescriptionHelpFormatter,
                                     usage='%(prog)s -p parser [options] [input files]')

    # Required arguments
    parser.add_argument("-o",
                        default = os.path.join(mwcproot, "mwcp", "parsertests"), 
                        type = str,
                        dest = "test_case_dir",
                        help = "Directory containing JSON test case files.")
    parser.add_argument("-r",
                        default = os.path.join(mwcproot, "mwcp", "resources"),
                        type = str,
                        dest = "resource_dir",
                        help = "Resource directory utilized by malware config reporter.")

    # Arguments used to run test cases
    parser.add_argument("-t",
                        default = False,
                        dest = "run_tests",
                        action = "store_true",
                        help = "Run test cases. Optional filters can be given using '-p' and/or '-k' arguments.")
    parser.add_argument("-p",
                        type = str,
                        dest = "parser_name",
                        default = "",
                        help = "parser")
    parser.add_argument("-k",
                        type = str,
                        dest = "field_names",
                        default = "",
                        help = "Fields (csv) to compare results for. Reference 'fields.json'. " +
                               "Ex. socketaddress,registrykey")    

    parser.add_argument("-x",
                        type = str,
                        dest = "exclude_field_names",
                        default = ",".join(DEFAULT_EXCLUDE_FIELDS),
                        help = "Fields (csv) excluded from test cases/comparisons. default: %(default)s")    
                               
    # Arguments used to generate and update test cases
    parser.add_argument("-i",
                        dest = "input_file",
                        action="store_true",
                        default=False,
                        help = "single input file provides a list of files to use as input, one per line")

    parser.add_argument("-u",
                        default = False,
                        dest = "update",
                        action = "store_true",
                        help = "Update all stored test cases with newly produced results.")

    parser.add_argument("-a",
                        default = False,
                        dest = "all_tests",
                        action = "store_true",
                        help = "select all available parsers, used with -t to test all parsers")                        
    parser.add_argument("-d",
                        default = False,
                        dest = "delete",
                        action = "store_true",
                        help = "delete file(s) from test cases")                                                
    
    # Arguments to configure console output
    parser.add_argument("-f",
                        default = False,
                        action = "store_true",
                        dest = "only_failed_tests",
                        help = "Display only failed test case details.")
    parser.add_argument("-v",
                        default = False,
                        action = "store_true",
                        dest = "verbose",
                        help = "Verbose output.")
    parser.add_argument("-j",
                        default = False,
                        action = "store_true",
                        dest = "json",
                        help = "JSON formatted output.")
    parser.add_argument("-s",
                        default = False,
                        action = "store_true",
                        dest = "silent",
                        help = "Limit output to statement saying whether all tests passed or not.")
    
    return parser

def main():
    ''' Run tool. '''

    print ''

    # Setup
    mwcproot = ""
    if os.path.dirname(sys.argv[0]):
        mwcproot = os.path.dirname(sys.argv[0])
        
    # Get command line arguments
    argparser = get_arg_parser(mwcproot)
    args, input_files = argparser.parse_known_args()

    
    # Configure reporter based on args
    if args.resource_dir:
        reporter = malwareconfigreporter(resourcedir = args.resource_dir,
                                         disableoutputfiles = True)
    else:
        reporter = malwareconfigreporter(disableoutputfiles = True)

    # Configure test object
    tester = malwareconfigtester(reporter = reporter, results_dir = args.test_case_dir)

    parser_descriptions = reporter.get_parser_descriptions()
    valid_parser_names = [x[0] for x in parser_descriptions]
    
    parsers = []
    if args.parser_name:
        if args.parser_name in valid_parser_names:
            parsers = [ args.parser_name ]
        else:
            print "Error: Invalid parser name(s) specified. Parser names are case sensitive."
            exit(1)
    if args.all_tests:
        parsers = valid_parser_names
    
    if not parsers:
        print "You must specify the parser to run (or run all parsers)"
        exit(2)
    
    if args.parser_name:
        results_file_path = tester.get_results_filepath(args.parser_name)
    
    #gather all our input files
    if args.input_file:
        input_files = read_input_list(input_files[0])

    
    # Default is to run test cases
    if args.run_tests:
        print "Running test cases. May take a while..."
        all_passed, test_results = tester.run_tests(parsers, filter(None,args.field_names.split(",")), 
                                                    ignore_field_names = filter(None, args.exclude_field_names.split(",")))
        print "All Passed = {0}\n".format(all_passed)
        if not args.silent:
            if args.only_failed_tests:
                tester.print_test_results(test_results,
                                          failed_tests = True,
                                          passed_tests = False,
                                          verbose = args.verbose,
                                          json_format = args.json)
            else:
                tester.print_test_results(test_results,
                                          failed_tests = True,
                                          passed_tests = True,
                                          verbose = args.verbose,
                                          json_format = args.json)
        if all_passed:
            exit(0)
        else:
            exit(1)
    
    #add files to test cases
    elif args.delete:
        removed_files = tester.remove_test_results(args.parser_name, input_files)
        for filename in removed_files:
            print("Removing results for %s in %s" % (filename, results_file_path))
    elif args.update or (not args.delete and input_files):
        if args.update:
            input_files.extend(tester.list_test_files(args.parser_name))
    
        for input_file in input_files:
            metadata = tester.gen_results(parser_name = args.parser_name, input_file_path = input_file)
            if len(metadata) > 1 and len(reporter.errors) == 0:
                print("Updating results for %s in %s" % (input_file, results_file_path))
                tester.update_test_results(results_file_path = results_file_path,
                                               results_data = metadata,
                                               replace = True)
            elif len(metadata) > 1 and len(reporter.errors) > 0:
                print("Error occurred for %s in %s, not updating" % (input_file, results_file_path))
            else:
                print("Empty results for %s in %s, not updating" % (input_file, results_file_path))
    else:
        argparser.print_help()

def read_input_list(filename):
    inputfilelist = []
    if filename:
        if filename == "-":
            inputfilelist = [ line.rstrip() for line in sys.stdin ]
        else:
            with open(filename,"rb") as f:
                inputfilelist = [ line.rstrip() for line in f ]

    return inputfilelist    


    
if __name__ == "__main__":
    main()
