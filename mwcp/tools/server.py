#!/usr/bin/env python

"""
DC3-MWCP server--simple REST API using bottle framework. Can be used as a standalone server or in
a wsgi server.

Requires bottle to be installed which can be done by putting bottle.py in the same directory as
this file.
"""

import hashlib
import json
import logging
import os
import sys
import traceback

local_path = os.path.dirname(__file__)
if local_path not in sys.path:
    sys.path.append(local_path)

from bottle import Bottle, run, request, response

import mwcp
import mwcp.parsers

logger = logging.getLogger("mwcp-server")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


DEFAULT_PAGE = '''<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    <html>
        <head>
            <title>DC3-MWCP Service</title>
        </head>
        <body>
            <h2>DC3-MWCP Service</h2>
            <br />
            <a href="descriptions">Module Descriptions</a>
        </body>
    </html>'''

app = Bottle()


@app.post('/run_parser/<parser>')
def run_parser(parser):
    """
    Execute a parser

    parser (url component): mwcp parser to use
    data (form file submission): data on which parser operates
    """

    datafile = request.files.get('data')
    if datafile:
        data = datafile.file.read()
        logger.info("run_parser %s %s %s" %
                    (parser, datafile.filename, hashlib.md5(data).hexdigest()))
        return _run_parser(parser, data=data)
    else:
        logger.error("run_parser %s no input file" % parser)
        return {'errors': ['No input file provided']}


@app.post('/run_parsers/<parsers:path>')
def run_parsers(parsers):
    """
    Execute multiple parsers on the same input file

    parsers (url components): mwcp parsers to use
    data (form file submission): data on which parser operates
    """

    output = {}
    datafile = request.files.get('data')
    if datafile:
        data = datafile.file.read()
        logger.info("run_parsers %s %s %s" %
                    (parsers, datafile.filename, hashlib.md5(data).hexdigest()))
        for parser in parsers.split("/"):
            if parser:
                output[parser] = _run_parser(parser, data=data)
    else:
        output['errors'] = ['No input file provided']
        logger.error("run_parsers %s no input file" % parsers)
    return output


@app.get('/')
def default():
    return DEFAULT_PAGE


@app.get('/descriptions')
def descriptions():
    """
    List descriptions of parser modules
    """

    try:
        response.content_type = "application/json"
        return json.dumps(mwcp.get_parser_descriptions(), indent=4)
    except Exception:
        output = {'errors': [traceback.format_exc()]}
        logger.error("descriptions %s" % (traceback.format_exc()))
        return output


def _run_parser(name, data=b'', append_output_text=True):
    output = {}
    logger.info("__run_parser %s %s" % (name, hashlib.md5(data).hexdigest()))
    try:
        reporter = mwcp.Reporter(base64_output_files=True)
        reporter.run_parser(name, data=data)
        output = reporter.metadata
        if reporter.errors:
            output["errors"] = reporter.errors
            for error in reporter.errors:
                logger.error("_run_parser %s %s" % (name, error))
        if append_output_text:
            output["output_text"] = reporter.get_output_text()
        return output
    except Exception:
        output = {'errors': [traceback.format_exc()]}
        logger.error("__run_parser %s %s" % (name, traceback.format_exc()))
        return output


def main():
    import argparse
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--parserdir', help='Parser directory to use.')
    argparser.add_argument('--parserconfig', help='Parser configuration file to use')
    argparser.add_argument(
        '--parsersource',
        help='Default parser source to use. Otherwise parsers from all sources are available.')
    options = argparser.parse_args()

    if options.parserdir:
        mwcp.register_parser_directory(options.parserdir, config_file_path=options.parserconfig)
        print('Set parser directory to: {}'.format(options.parserdir))
    else:
        mwcp.register_entry_points()

    if options.parsersource:
        mwcp.set_default_source(options.parsersource)

    run(app, server='auto', host='localhost', port=8080)


if __name__ == '__main__':
    main()
else:
    mwcp.register_entry_points()
    application = app
