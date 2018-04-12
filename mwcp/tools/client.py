#!/usr/bin/env python
"""
DC3-MWCP client tool--submit files to the mwcp-server
"""
from __future__ import print_function

import os
import sys
import argparse
import json
import requests
import hashlib
import traceback
import base64

from six import iteritems


def get_descriptions(host):
    """
    Return list containing parser names, authors, and descriptions.
    """

    url = "http://{0}/descriptions".format(host)
    try:
        response = requests.get(url)
        return json.loads(response.text)
    except:
        return {"error": traceback.format_exc()}


def get_descriptions_table(host):
    """
    Return formatted string with parser descriptions in table
    format.
    """

    string = "-------------------------------------------------\n"
    string += "{:<20} {:<15} {}\n".format("Name", "Author", "Description")
    string += "-------------------------------------------------\n"
    descriptions = get_descriptions(host)
    for name, author, description in descriptions:
        string += "{:<20} {:<15} {}\n".format(name, author, description)
    return string


def valid_parser(host, parser):
    """
    Check if parser name matches a parser name on the server.
    """

    descriptions = get_descriptions(host)
    if parser in [x[0] for x in descriptions]:
        return True
    return False


def run_parser(host, file_path, parser, timeout=300, modargs=None):
    """
    Run the provided file against the provided parser.
    """

    url = "http://{0}/run_parser/{1}".format(host, parser)
    files = {"data": open(file_path, "rb")}
    data = {"modargs": json.dumps(modargs or {})}

    try:
        response = requests.post(url, files=files, timeout=timeout, data=data)
        return json.loads(response.text)
    except:
        return {"error": traceback.format_exc()}


def output(args, response_json, filename, md5):
    """
    Output the provided json (dictionary) based on the given
    arguments. Either print to standard output or write to file.
    """

    output_path = args.output if args.output else ""

    # Output results
    if args.output is None:
        print(json.dumps(response_json, indent=4))
    else:
        output_file = os.path.join(
            args.output, "{0}_{1}.json".format(os.path.basename(filename), md5))
        with open(output_file, "w") as out:
            out.write(json.dumps(response_json, indent=4))

    # Output any files extracted from the config parser
    if "outputfile" in response_json and not args.disableparseroutputfiles:
        for entry in response_json["outputfile"]:
            name = entry[0]
            description = entry[1]
            md5 = entry[2]
            filedata = base64.b64decode(entry[3])
            with open(os.path.join(output_path, name), "wb") as f:
                f.write(filedata)


def md5(file):
    """
    Return MD5 hash of file.
    """

    hash = hashlib.md5()
    with open(file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()


def make_arg_parser():
    """
    Create an argument parser to handle command line inputs
    """

    usage_str = '%s [options] FILE' % (os.path.basename(sys.argv[0]))
    description = "DC3-MWCP client tool--submit files to the mwcp-server"
    arg_parser = argparse.ArgumentParser(description=description,
                                         usage=usage_str)

    arg_parser.add_argument("file",
                            nargs="?",
                            help="File or directory pointing to file(s) to parse.")
    arg_parser.add_argument("-l",
                            "--list",
                            action="store_true",
                            default=False,
                            help="List all malware config parsers.",
                            dest="list")
    arg_parser.add_argument("-H",
                            "--host",
                            default="localhost:8080",
                            dest="host",
                            help="Mwcp-server host. (default: localhost:8080)")
    arg_parser.add_argument("-o",
                            "--output",
                            default=None,
                            dest="output",
                            help="Output directory to place JSON files instead of standard out.\
                            Output filenames will have the format <filename>_<MD5>.json. The\
                            MD5 value is appended to ensure filename uniqueness in the output\
                            directory.")
    arg_parser.add_argument("-p",
                            "--parser",
                            default=None,
                            dest="parser",
                            help="Malware config parser to call. "
                                 "(use dot notation to specify source if necessary e.g. 'mwcp-acme.Foo')")
    arg_parser.add_argument("-t",
                            "--timeout",
                            default=300,
                            dest="timeout",
                            help="Timeout limit for running one file against one parser.")
    arg_parser.add_argument("-d",
                            "--disableparseroutputfiles",
                            action="store_true",
                            default=False,
                            help="Do not write files parsed out by config parsers.",
                            dest="disableparseroutputfiles")
    arg_parser.add_argument('-w',
                            '--kwargs',
                            default='',
                            dest='kwargs_raw',
                            help='module keyword arguments as json encoded dictionary\
                            if values in the dictionary use the special paradigm "b64file(filename)", then \
                            filename is read, base64 encoded, and used as the value')
    return arg_parser


def main():
    """Run tool."""

    arg_parser = make_arg_parser()
    args = arg_parser.parse_args()

    # List parser names and descriptions
    if args.list:
        print(get_descriptions_table(args.host))
        sys.exit(0)

    # Make sure a file or directory of files has been specified
    if args.file is None:
        arg_parser.print_help()
        sys.exit(1)

    # Verify that file/directory exists
    if not os.path.exists(args.file):
        print("File {0} not found".format(args.file))
        sys.exit(1)

    # Verify that the parser name is valid
    if not valid_parser(args.host, args.parser):
        print("Parser name {0} does not exist on the server.".format(
            args.parser))
        sys.exit(1)

    # Get any custom arguments
    kwargs = {}
    if args.kwargs_raw:
        kwargs = dict(json.loads(args.kwargs_raw))
        for key, value in iteritems(kwargs):
            if value and len(value) > len("b64file("):
                if value[:len("b64file(")] == "b64file(" and value[-1:] == ")":
                    tmp_filename = value[len("b64file("):-1]
                    with open(tmp_filename, "rb") as f:
                        kwargs[key] = base64.b64encode(f.read())

    # Run single file
    if os.path.isfile(args.file):
        response_json = run_parser(
            args.host, args.file, args.parser, timeout=args.timeout, modargs=kwargs)
        output(args, response_json, args.file, md5(args.file))
        sys.exit(0)

    # Recursively run directory of files
    if os.path.isdir(args.file):
        for root, dirs, files in os.walk(args.file):
            for file in files:
                file_path = os.path.join(os.path.abspath(root), file)
                response_json = run_parser(
                    args.host, file_path, args.parser, timeout=args.timeout, modargs=kwargs)
                output(args, response_json, file, md5(file_path))
        sys.exit(0)

    # Shouldn't get here
    sys.exit(1)

if __name__ == "__main__":
    main()
