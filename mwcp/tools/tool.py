#!/usr/bin/env python
"""
DC3-MWCP cli tool--makes available functionality of DC3-MWCP framework
"""
from __future__ import print_function, unicode_literals
from future.builtins import str, zip, open

import argparse
import base64
import csv
import datetime
import hashlib
import itertools
import json
import os
import sys
import tempfile
import time
import traceback

from six import iteritems

import mwcp
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
                metadata['other.{}'.format(sub_key)] = sub_value
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
    with open(csv_path, b'wb') as csvfile:
        dw = csv.DictWriter(csvfile, fieldnames=column_names)
        dw.writeheader()
        dw.writerows([
            {k: _format_metadata_value(v).encode('utf8') for k, v in metadata.items()}
            for metadata in results
        ])


def _print_parsers(json_output=False):
    """
    Prints a table of registered parsers to stdout.

    :param json_output: Print json
    """
    descriptions = mwcp.get_parser_descriptions()
    if json_output:
        print(json.dumps(descriptions, indent=4))
    else:
        # TODO: Use a library like tabulate to print this.
        format = '%-25s %-50s %-15s %s'
        print(format % ('NAME', 'SOURCE', 'AUTHOR', 'DESCRIPTION'))
        print('-' * 150)
        for name, source, author, description in descriptions:
            print(format % (name, source, author, description))


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
            with open(input_args[0], b"rb") as f:
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


def _parse_file(reporter, file_path, parser, options=None, include_filename=False):
    """
    Parses given file_path with given parser.

    :param reporter: Reporter to use for parsing.
    :param file_path: File path to parse or "-" for stdin
    :param parser: Name of parser to run (can use ":" notation)
    :param options: Extra arguments to pass along to parser.
    :param include_filename: Whether to include input file metadata in the results.
    :return: Dictionary of results.
    """
    options = options or {}
    if file_path == "-":
        reporter.run_parser(parser, data=sys.stdin.read(), **options)
    else:
        reporter.run_parser(parser, file_path, **options)

    result = reporter.metadata

    if include_filename:
        result['inputfilename'] = file_path
        result['md5'] = hashlib.md5(reporter.data).hexdigest()
        result['sha1'] = hashlib.sha1(reporter.data).hexdigest()
        result['sha256'] = hashlib.sha256(reporter.data).hexdigest()
        result['parser'] = parser
        if reporter.pe:
            result['compiletime'] = datetime.datetime.fromtimestamp(
                reporter.pe.FILE_HEADER.TimeDateStamp).isoformat()

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
    parser.add_argument("-l",
                        action="store_true",
                        default=False,
                        dest="list",
                        help="list all malware config parsers.")
    parser.add_argument("-k",
                        action="store_true",
                        default=False,
                        dest="fields",
                        help="List all standardized fields and examples. See resources/fields.json")
    parser.add_argument("-a", "--parserdir",
                        metavar="DIR",
                        default=default_parserdir,
                        dest="parserdir",
                        help="Parsers directory" + " [default: {}]".format(default_parserdir))
    parser.add_argument("-o",
                        metavar="DIR",
                        default="",
                        dest="outputdir",
                        help="Output directory.")
    parser.add_argument("-c",
                        metavar="CSVWRITE",
                        default="",
                        dest="csvwrite",
                        help="Output CSV file.")
    parser.add_argument("-t",
                        metavar="DIR",
                        default=tempfile.gettempdir(),
                        dest="tempdir",
                        help="Temp directory." + " [default: {}]".format(tempfile.gettempdir()))
    parser.add_argument("-j",
                        action="store_true",
                        default=False,
                        dest="jsonoutput",
                        help="Enable json output for parser reports (instead of formatted text).")
    parser.add_argument("-n",
                        action="store_true",
                        default=False,
                        dest="disableoutputfiles",
                        help="Disable writing output files to filesystem.")
    parser.add_argument("-g",
                        action="store_true",
                        default=False,
                        dest="disabletempcleanup",
                        help="Disable cleanup of framework created temp files including managed tempdir.")
    parser.add_argument("-f",
                        action="store_true",
                        default=False,
                        dest="includefilename",
                        help="Include file information such as filename, hashes, and compile time in parser output.")
    parser.add_argument("-d",
                        action="store_true",
                        default=False,
                        dest="hidedebug",
                        help="Hide debug messages in output.")
    parser.add_argument("-u",
                        metavar="FILENAME",
                        default="",
                        dest="outputfile_prefix",
                        help="String prepended to output files written to filesystem. Specifying 'md5' will cause " +
                             "output files to be prefixed with the md5 of the input file. When passing in multiple " +
                             "files for analysis, the default will be 'md5'. Passing in a value with the -u option " +
                             "or using the -U option can be used to override the 'md5' default for multiple files. " +
                             "[default: (No prefix|md5)]")
    parser.add_argument("-U",
                        action="store_true",
                        default=False,
                        dest="disableoutputfileprefix",
                        help="When in effect, parser output files will not have a filename prefix.")
    parser.add_argument("-i",
                        action="store_true",
                        default=False,
                        dest="filelistindirection",
                        help="Input file contains a list of filenames to process.")
    parser.add_argument("-b",
                        action="store_true",
                        default=False,
                        dest="base64outputfiles",
                        help="Base64 encode output files and include in metadata.")
    parser.add_argument("-w",
                        metavar="JSON",
                        default="",
                        dest="kwargs_raw",
                        help="Module keyword arguments as json encoded dictionary " +
                             "if values in the dictionary use the special paradigm 'b64file(filename)', then " +
                             "filename is read, base64 encoded, and used as the value)")

    return parser


def main():
    argparser = get_arg_parser()
    args, input_files = argparser.parse_known_args()

    # This is a preliminary check before creating the reporter to establish how output
    # file prefixes should be set.
    if args.disableoutputfileprefix:
        args.outputfile_prefix = ''
    elif args.filelistindirection or len(input_files) > 1 or any([os.path.isdir(x) for x in input_files]):
        args.outputfile_prefix = 'md5'

    if args.list:
        if args.parserdir:
            mwcp.register_parser_directory(args.parserdir)
        _print_parsers(json_output=args.jsonoutput)
        sys.exit(0)

    if args.fields:
        _print_fields(json_output=args.jsonoutput)
        sys.exit(0)

    if not input_files or not args.parser:
        argparser.print_help()
        sys.exit(0)

    file_paths = _get_file_paths(input_files, is_filelist=args.filelistindirection)

    kwargs = {}
    if args.kwargs_raw:
        kwargs = dict(json.loads(args.kwargs_raw))
        for key, value in list(kwargs.items()):
            if value and value.startswith('b64file(') and value.endswith(')'):
                tmp_filename = value[len('b64file('):-1]
                with open(tmp_filename, b'rb') as f:
                    kwargs[key] = base64.b64encode(f.read())

    # Run MWCP
    try:
        reporter = mwcp.Reporter(parserdir=args.parserdir,
                            outputdir=args.outputdir,
                            outputfile_prefix=args.outputfile_prefix,
                            tempdir=args.tempdir,
                            disabledebug=args.hidedebug,
                            disableoutputfiles=args.disableoutputfiles,
                            disabletempcleanup=args.disabletempcleanup,
                            base64outputfiles=args.base64outputfiles)
        results = []
        for file_path in file_paths:
            result = _parse_file(
                reporter, file_path, args.parser, options=kwargs, include_filename=args.includefilename)
            results.append(result)
            if not args.jsonoutput:
                reporter.print_report()

        if args.csvwrite:
            csv_path = args.csvwrite
            if not csv_path.endswith('.csv'):
                csv_path += '.csv'
            _write_csv(input_files, results, csv_path, args.base64outputfiles)
            if not args.jsonoutput:
                print('Wrote csv file: {}'.format(csv_path))

        if args.jsonoutput:
            print(json.dumps(results, indent=4))

    except Exception as e:
        error_message = "Error running DC3-MWCP: {}".format(e)
        if args.jsonoutput:
            print(json.dumps({'errors': [error_message]}))
        else:
            print(error_message)
        sys.exit(1)


if __name__ == '__main__':
    main()
