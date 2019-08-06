#!/usr/bin/env python
"""
DC3-MWCP cli tool--makes available functionality of DC3-MWCP framework
"""
from __future__ import print_function
from future.builtins import str, zip, open

import argparse
import base64
import csv
import datetime
import hashlib
import itertools
import json
import logging
import os
import sys
import tabulate
import tempfile
import time
import traceback
import warnings

from six import iteritems

import mwcp
import mwcp.parsers
from mwcp.utils.stringutils import convert_to_unicode


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
        for field, value in iteritems(v):
            if isinstance(value, (list, tuple)):
                value = u'[{}]'.format(u', '.join(value))

            result += u'{}: {}\n'.format(field, value)
        return result.rstrip()
    else:
        return convert_to_unicode(v)


def _write_csv(input_files, results, csv_path, base64_outputfiles=False):
    """
    Writes out results as a csv.

    :param input_files: List of filenames for each respective metadata.
    :param results: List of metadata dictionaries.
    :param csv_path: Path to write out csv file.
    :param base64_outputfiles: Whether to include base64 outputfiles.
    :raises IOError: If csv could not be written out.
    """
    scan_date = time.ctime()

    # Add/Teak metadata.
    for inputfilename, metadata in zip(input_files, results):
        # Add scan date.
        metadata['scan_date'] = scan_date
        if 'inputfilename' not in metadata:
            metadata['inputfilename'] = inputfilename

        # Flatten 'other' entry so nested values get their own columns,
        # are more readable, and easier to individually analyze.
        #
        # Example:
        #   {'other': {"unique_entry": "value", "unique_key": "value2"}}
        #   Results in columns: other, other.unique_entry, other.unique_key
        if 'other' in metadata:
            for sub_key, sub_value in metadata['other'].items():
                metadata['other.{}'.format(convert_to_unicode(sub_key))] = sub_value
            del metadata['other']

        # Split outputfile into multiple fields.
        if 'outputfile' in metadata:
            value = list(zip(*metadata['outputfile']))
            metadata['outputfile.name'] = value[0]
            metadata['outputfile.description'] = value[1]
            metadata['outputfile.md5'] = value[2]
            if len(value) > 3 and base64_outputfiles:
                metadata['outputfile.base64'] = value[3]
            del metadata['outputfile']

    # Sort columns, but with PREFIX_COLUMNS showing up first.
    column_names = set(itertools.chain(*(metadata.keys() for metadata in results)))
    column_names = sorted(
        column_names, key=lambda x: str(_STD_CSV_COLUMNS.index(x)) if x in _STD_CSV_COLUMNS else x)

    # Reformat metadata and write to CSV
    with open(csv_path, 'wb' if sys.version_info.major < 3 else 'w') as csvfile:
        dw = csv.DictWriter(csvfile, fieldnames=column_names, lineterminator='\n')
        dw.writeheader()
        for metadata in results:
            dw.writerow({k: _format_metadata_value(v) for k, v in metadata.items()})


def _print_parsers(json_output=False, config_only=True):
    """
    Prints a table of registered parsers to stdout.

    :param json_output: Print json
    :param config_only: Whether to only print parsers listed in configuration file.
    """
    descriptions = mwcp.get_parser_descriptions(config_only=config_only)
    if json_output:
        print(json.dumps(descriptions, indent=4))
    else:
        print(tabulate.tabulate(descriptions, headers=['NAME', 'SOURCE', 'AUTHOR', 'DESCRIPTION']))


def _print_fields(json_output=False):
    """
    Prints a table of available metadata fields to stdout.

    :param json_output: Print json
    :return:
    """
    # TODO: reporter shouldn't be generating the fields.
    reporter = mwcp.Reporter()
    fields = reporter.fields
    if json_output:
        print(json.dumps(fields, indent=4))
    else:
        for name, value in sorted(fields.items()):
            print('%-20s %s' % (name, value['description']))
            for example in value['examples']:
                print("{} {}".format(" " * 24, json.dumps(example)))


def _get_file_paths(input_args, is_filelist=True):
    """
    Gets valid file paths from the given input args.
    :param input_args: Input arguments passed through in the cli
    :param is_filelist: Whether input_args is a file containing a list of file paths.
    :return: A list of file paths.
    """
    if is_filelist:
        if input_args[0] == "-":
            return [line.rstrip() for line in sys.stdin]
        else:
            with open(input_args[0], "r") as f:
                return [line.rstrip() for line in f]
    else:
        file_paths = []
        for arg in input_args:
            if os.path.isfile(arg):
                file_paths.append(arg)
            elif os.path.isdir(arg):
                for root, dirs, files in os.walk(arg):
                    for file in files:
                        file_paths.append(os.path.join(root, file))
        return file_paths


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


def get_arg_parser():
    """
    create a option parser to handle command line inputs
    """
    usage_str = 'usage:  %s [options] FILES_DIRS' % (os.path.basename(sys.argv[0]))
    description = "DC3-MWCP Framework: utility for executing parser modules"
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     usage=usage_str)
    default_parserdir = ''

    # Create reporter to get default paths, ignore if this fails
    try:
        default_reporter = mwcp.Reporter()
        default_parserdir = default_reporter.parserdir
    except Exception:
        pass

    parser.add_argument("-p",
                        default="",
                        type=str,
                        dest="parser",
                        help="Malware config parser to call. (use ':' notation to specify source if necessary e.g. 'mwcp-acme:Foo')")
    parser.add_argument("-l", "--parsers",
                        default=0,
                        action="count",
                        dest="list",
                        help="list all malware config parsers. (use -ll to also list component parsers)")
    parser.add_argument("-k", "--fields",
                        action="store_true",
                        default=False,
                        dest="fields",
                        help="List all standardized fields and examples. See resources/fields.json")
    parser.add_argument("--parserdir",
                        metavar="DIR",
                        default=None,
                        dest="parserdir",
                        help="Optional extra parser directory")
    parser.add_argument("--parserconfig",
                        metavar="FILE",
                        default=None,
                        dest="parserconfig",
                        help="Optional parser configuration file to use with extra parser directory.")
    parser.add_argument("--parsersource",
                        metavar="SOURCE_NAME",
                        default=None,
                        dest="parsersource",
                        help="Set a default parser source to use. "
                             "If not provided parsers from all sources will be available.")
    parser.add_argument("-o", "--outputdir",
                        metavar="DIR",
                        default="",
                        dest="outputdir",
                        help="Output directory.")
    parser.add_argument("-c", "--csv",
                        metavar="CSVWRITE",
                        default="",
                        dest="csvwrite",
                        help="Output CSV file.")
    parser.add_argument("-t", "--tempdir",
                        metavar="DIR",
                        default=tempfile.gettempdir(),
                        dest="tempdir",
                        help="Temp directory." + " [default: {}]".format(tempfile.gettempdir()))
    parser.add_argument("-j", "--json",
                        action="store_true",
                        default=False,
                        dest="jsonoutput",
                        help="Enable json output for parser reports (instead of formatted text).")
    parser.add_argument("-n", "--disable_output",
                        action="store_true",
                        default=False,
                        dest="disableoutputfiles",
                        help="Disable writing output files to filesystem.")
    parser.add_argument("-g", "--disable-temp-cleanup",
                        action="store_true",
                        default=False,
                        dest="disabletempcleanup",
                        help="Disable cleanup of framework created temp files including managed tempdir.")
    parser.add_argument("-f", "--include-filename",
                        action="store_true",
                        default=False,
                        dest="includefilename",
                        help="Include file information such as filename, hashes, and compile time in parser output.")
    # TODO: Determine if we can remove this option. It is conflicting what we call "debug".
    parser.add_argument("--no-debug",
                        action="store_true",
                        default=False,
                        dest="hidedebug",
                        help="Hide debug messages in output.")
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        default=False,
                        dest="debug",
                        help="Turn on all debugging messages. (WARNING: This WILL spam the console)")
    parser.add_argument("-u", "--output-prefix",
                        metavar="FILENAME",
                        default="",
                        dest="outputfile_prefix",
                        help="String prepended to output files written to filesystem. Specifying 'md5' will cause " +
                             "output files to be prefixed with the md5 of the input file. When passing in multiple " +
                             "files for analysis, the default will be 'md5'. Passing in a value with the -u option " +
                             "or using the -U option can be used to override the 'md5' default for multiple files. " +
                             "[default: (No prefix|md5)]")
    parser.add_argument("-U", "--no-output-prefix",
                        action="store_true",
                        default=False,
                        dest="disableoutputfileprefix",
                        help="When in effect, parser output files will not have a filename prefix.")
    parser.add_argument("-i", "--filelist",
                        action="store_true",
                        default=False,
                        dest="filelistindirection",
                        help="Input file contains a list of filenames to process.")
    parser.add_argument("-b", "--base64",
                        action="store_true",
                        default=False,
                        dest="base64outputfiles",
                        help="Base64 encode output files and include in metadata.")

    return parser


def main(args=None):
    warnings.warn("WARNING: mwcp-tool is deprecated. Please use \"mwcp parse\" instead.")

    argparser = get_arg_parser()
    args, input_files = argparser.parse_known_args(args)

    # Setup logging
    mwcp.setup_logging()
    if args.hidedebug:
        logging.root.setLevel(logging.WARNING)
    elif args.debug:
        logging.root.setLevel(logging.DEBUG)

    # This is a preliminary check before creating the reporter to establish how output
    # file prefixes should be set.
    if args.disableoutputfileprefix:
        args.outputfile_prefix = ''
    elif args.filelistindirection or len(input_files) > 1 or any([os.path.isdir(x) for x in input_files]):
        args.outputfile_prefix = 'md5'

    if args.fields:
        _print_fields(json_output=args.jsonoutput)
        sys.exit(0)

    # Register parsers
    mwcp.register_entry_points()
    if args.parserdir:
        mwcp.register_parser_directory(args.parserdir, config_file_path=args.parserconfig)

    if args.parsersource:
        mwcp.set_default_source(args.parsersource)

    if args.list:
        _print_parsers(json_output=args.jsonoutput, config_only=args.list < 2)
        sys.exit(0)

    if not input_files or not args.parser:
        argparser.print_help()
        sys.exit(0)

    file_paths = _get_file_paths(input_files, is_filelist=args.filelistindirection)

    # Run MWCP
    try:
        if args.outputfile_prefix:
            warnings.warn('WARNING: --outputfile-prefix argument is no longer supported and will be ignored.')
        reporter = mwcp.Reporter(
            outputdir=args.outputdir,
            tempdir=args.tempdir,
            disable_output_files=args.disableoutputfiles,
            disable_temp_cleanup=args.disabletempcleanup,
            base64_output_files=args.base64outputfiles)
        results = []
        for file_path in file_paths:
            result = _parse_file(
                reporter, file_path, args.parser, include_filename=args.includefilename)
            results.append(result)
            if not args.jsonoutput:
                reporter.print_report()

        if args.csvwrite:
            csv_path = args.csvwrite
            _write_csv(file_paths, results, csv_path, args.base64outputfiles)
            if not args.jsonoutput:
                print('Wrote csv file: {}'.format(csv_path))

        if args.jsonoutput:
            print(json.dumps(results, indent=4))

    except Exception as e:
        error_message = "Error running DC3-MWCP: {}".format(e)
        traceback.print_exc()
        if args.jsonoutput:
            print(json.dumps({'errors': [error_message]}))
        else:
            print(error_message)
        sys.exit(1)


if __name__ == '__main__':
    main()
