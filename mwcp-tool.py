#!/usr/bin/env python
"""
DC3-MWCP cli tool--makes available functionality of DC3-MWCP framework
"""
from __future__ import print_function

import os
import sys
import argparse
import traceback
import hashlib
import datetime
import tempfile
import json
import base64
import time
import csv

from mwcp.malwareconfigreporter import malwareconfigreporter

from six import iteritems


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
    default_resourcedir = ''

    # Create reporter to get default paths, ignore if this fails
    try:
        default_reporter = malwareconfigreporter()
        default_parserdir = default_reporter.parserdir
        default_resourcedir = default_reporter.resourcedir
    except Exception:
        pass

    parser.add_argument("-p",
                        default="",
                        type=str,
                        dest="parser",
                        help="Malware config parser to call.")
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
    parser.add_argument("-a",
                        metavar="DIR",
                        default=default_parserdir,
                        dest="parserdir",
                        help="Parsers directory" + " [default: {}]".format(default_parserdir))
    parser.add_argument("-r",
                        metavar="DIR",
                        default=default_resourcedir,
                        dest="resourcedir",
                        help="Resources directory" + " [default: {}]".format(default_resourcedir))
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

    # If we can not create reporter object there is very little we can do. Just die immediately.
    try:
        reporter = malwareconfigreporter(parserdir=args.parserdir,
                                         resourcedir=args.resourcedir,
                                         outputdir=args.outputdir,
                                         outputfile_prefix=args.outputfile_prefix,
                                         tempdir=args.tempdir,
                                         disabledebug=args.hidedebug,
                                         disableoutputfiles=args.disableoutputfiles,
                                         disabletempcleanup=args.disabletempcleanup,
                                         base64outputfiles=args.base64outputfiles)
    except Exception:
        error_message = "Error loading DC3-MWCP reporter object, please check installation: {}".format(traceback.format_exc())
        if args.jsonoutput:
            print('{"errors": ["{}"]}'.format(error_message))
        else:
            print(error_message)
        sys.exit(1)

    if args.list:
        descriptions = reporter.get_parser_descriptions()

        if args.jsonoutput:
            if reporter.errors:
                descriptions.append({"errors": reporter.errors})
            print(reporter.pprint(descriptions))
        else:
            for name, author, description in descriptions:
                print('%-25s %-8s %s' % (name, author, description))
            if reporter.errors:
                print("")
                print("Errors:")
                for error in reporter.errors:
                    print("    {}".format(error))
        return

    if args.fields:
        if args.jsonoutput:
            print(reporter.pprint(reporter.fields))
        else:
            for key in sorted(reporter.fields):
                print('%-20s %s' % (key, reporter.fields[key]['description']))
                for example in reporter.fields[key]['examples']:
                    print("{} {}".format(" " * 24, json.dumps(example)))
        return

    if not input_files:
        argparser.print_help()
        return

    if args.parser:
        if args.filelistindirection:
            if input_files[0] == "-":
                inputfilelist = [line.rstrip() for line in sys.stdin]
            else:
                with open(input_files[0], "rb") as f:
                    inputfilelist = [line.rstrip() for line in f]
        else:
            inputfilelist = []
            for arg in input_files:
                if os.path.isfile(arg):
                    inputfilelist.append(arg)
                elif os.path.isdir(arg):
                    for root, dirs, files in os.walk(arg):
                        for file in files:
                            inputfilelist.append(os.path.join(root, file))

        kwargs = {}
        if args.kwargs_raw:
            kwargs = dict(json.loads(args.kwargs_raw))
            for key, value in iteritems(kwargs):
                if value and len(value) > len("b64file("):
                    if value[:len("b64file(")] == "b64file(" and value[-1:] == ")":
                        tmp_filename = value[len("b64file("):-1]
                        with open(tmp_filename, "rb") as f:
                            kwargs[key] = base64.b64encode(f.read())
        json_accum = []
        for inputfilename in inputfilelist:
            if inputfilename == "-":
                reporter.run_parser(args.parser, data=sys.stdin.read(), **kwargs)
            else:
                reporter.run_parser(args.parser, inputfilename, **kwargs)

            if args.includefilename:
                reporter.metadata['inputfilename'] = inputfilename
                reporter.metadata['md5'] = hashlib.md5(reporter.data).hexdigest()
                reporter.metadata['sha1'] = hashlib.sha1(reporter.data).hexdigest()
                reporter.metadata['sha256'] = hashlib.sha256(reporter.data).hexdigest()
                reporter.metadata['parser'] = args.parser
                if reporter.pe:
                    reporter.metadata['compiletime'] = datetime.datetime.fromtimestamp(reporter.pe.FILE_HEADER.TimeDateStamp).isoformat()

            output = reporter.metadata
            if reporter.errors:
                output["errors"] = reporter.errors
            json_accum.append(output)

            if not args.jsonoutput:
                reporter.output_text()

        if args.jsonoutput:
            print(reporter.pprint(json_accum if len(json_accum) > 1 else json_accum[0]))

        if args.csvwrite:
            csv_filename = args.csvwrite
            if not csv_filename.endswith('.csv'):
                csv_filename += '.csv'

            if json_accum:
                key_list = []

                # Begin flushing out CSV column names. A column needs to exist for
                # for each unique field in all the produced results.
                # 1 key_list entry = 1 column name
                for metadata in json_accum:
                    key_list.extend(list(metadata.keys()))
                    additional_other_keys = []

                    # Flatten 'other' entries so nested values get their own columns,
                    # are more readable, and easier to individually analyze.
                    #
                    # Example:
                    #   {'other': {"unique_entry": "value", "unique_key": "value2"}}
                    #   Results in columns: other, other.unique_entry, other.unique_key
                    if 'other' in metadata:
                        other_dict = metadata['other']
                        additional_other_keys = ['other.' + other_key for other_key in list(other_dict.keys())]

                        # Append the metadata to include these more isolated key value pairs
                        for i, value in enumerate(other_dict.values()):
                            metadata[additional_other_keys[i]] = value

                    key_list += additional_other_keys

                # Make sure all column names are unique
                key_list = list(set(key_list))

                # Flatten 'outputfile' field into separate columns for easier viewing and analysis.
                if 'outputfile' in key_list:
                    if args.base64outputfiles:
                        key_list = ['outputfile.name', 'outputfile.description', 'outputfile.md5', 'outputfile.base64'] + key_list
                    else:
                        key_list = ['outputfile.name', 'outputfile.description', 'outputfile.md5'] + key_list

                # Add timestamp and input filename as first columns for readability. Remaining
                # columns are sorted to sift through them easier.
                scan_date = time.ctime()
                if 'inputfilename' in key_list:
                    key_list.remove('inputfilename')
                key_list = ['scan_date', 'inputfilename'] + sorted(key_list)

                # Reformat result metadata to:
                #   1. Populate the newly added fields to the keylist
                #   2. Reformat values that are lists and dictionaries to be more readable
                for i, metadata in enumerate(json_accum):

                    # Populate the newly created outputfile fields
                    if 'outputfile' in list(metadata.keys()):
                        metadata['outputfile.name'] = [outp[0] for outp in metadata['outputfile']]
                        metadata['outputfile.description'] = [outp[1] for outp in metadata['outputfile']]
                        metadata['outputfile.md5'] = [outp[2] for outp in metadata['outputfile']]
                        if len(outp) > 3 and args.base64outputfiles is True:
                            metadata['outputfile.base64'] = [outp[3] for outp in metadata['outputfile']]

                    # Reformat lists and dictionaries as string values
                    for k, v in iteritems(metadata):
                        if isinstance(v, basestring):
                            metadata[k] = reporter.convert_to_unicode(v)
                        elif isinstance(v, list):
                            metadata[k] = u''
                            for j in v:
                                if not isinstance(j, basestring):
                                    metadata[k] += u'{}\n'.format(u', '.join([reporter.convert_to_unicode(item) for item in j]))
                                else:
                                    metadata[k] += u'{}\n'.format(reporter.convert_to_unicode(j))
                            metadata[k] = metadata[k].rstrip()
                        elif isinstance(v, dict):
                            metadata[k] = u''
                            for field, value in iteritems(v):
                                if isinstance(value, list):
                                    value = u'[{}]'.format(u', '.join(value))

                                metadata[k] += u'{}: {}\n'.format(field, value)
                            metadata[k] = metadata[k].rstrip()
                        else:
                            metadata[k] = reporter.convert_to_unicode(v)

                    # Populate the newly added scan_date and inputfilename fields
                    metadata['scan_date'] = scan_date
                    if 'inputfilename' not in list(metadata.keys()):
                        metadata['inputfilename'] = inputfilelist[i]

                # Write reformatted metadata results to CSV
                try:
                    with open(csv_filename, 'wb') as csvfile:
                        dw = csv.DictWriter(csvfile, fieldnames=key_list)
                        dw.writeheader()
                        dw.writerows([{k: v.encode('utf8') for k, v in list(entry.items())} for entry in json_accum])
                except IOError as exc:
                    print('\nUnable to write %s (%s)' % (csv_filename, exc.args[1]))


if __name__ == '__main__':
    main()
