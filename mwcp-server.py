#!/usr/bin/env python

"""
DC3-MWCP server--simple REST API using bottle framework. Can be used as a standalone server or in
a wsgi server.

Requires bottle to be installed which can be done by putting bottle.py in the same directory as
this file.
"""

import os
import sys
import traceback
import json
import logging
import hashlib

local_path = os.path.dirname(__file__)
if local_path not in sys.path:
    sys.path.append(local_path)

from mwcp.malwareconfigreporter import malwareconfigreporter
from bottle import Bottle, run, request, response

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
    modargs (form data): arguments passed to parsers (used very infrequently)
    """

    datafile = request.files.get('data')
    modargs = request.forms.get("modargs")
    if datafile:
        data = datafile.file.read()
        logger.info("run_parser %s %s %s" %
                    (parser, datafile.filename, hashlib.md5(data).hexdigest()))
        return __run_parser(parser, data=data, modargs=modargs)
    else:
        logger.error("run_parser %s no input file" % (parser))
        return {'errors': ['No input file provided']}


@app.post('/run_parsers/<parsers:path>')
def run_parsers(parsers):
    """
    Execute multiple parsers on the same input file

    parsers (url components): mwcp parsers to use
    data (form file submission): data on which parser operates
    modargs (form data): arguments passed to parsers (used very infrequently)
    """

    output = {}
    datafile = request.files.get('data')
    modargs = request.forms.get("modargs")
    if datafile:
        data = datafile.file.read()
        logger.info("run_parsers %s %s %s" %
                    (parsers, datafile.filename, hashlib.md5(data).hexdigest()))
        for parser in parsers.split("/"):
            if parser:
                output[parser] = __run_parser(
                    parser, data=data, modargs=modargs)
    else:
        output['errors'] = ['No input file provided']
        logger.error("run_parsers %s no input file" % (parsers))
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
        reporter = malwareconfigreporter(
            base64outputfiles=True, disableoutputfiles=True)
        return reporter.pprint(reporter.get_parser_descriptions())
    except Exception:
        output = {}
        output['errors'] = [traceback.format_exc()]
        logger.error("descriptions %s" % (traceback.format_exc()))
        return output


def __run_parser(name, data='', modargs='', append_output_text=True):
    output = {}
    logger.info("__run_parser %s %s" % (name, hashlib.md5(data).hexdigest()))
    try:
        reporter = malwareconfigreporter(base64outputfiles=True)
        kwargs = {}
        if modargs:
            kwargs = dict(json.loads(modargs))
        reporter.run_parser(name, data=data, **kwargs)
        output = reporter.metadata
        if reporter.errors:
            output["errors"] = reporter.errors
            for error in reporter.errors:
                logger.error("__run_parser %s %s" % (name, error))
        if append_output_text:
            output["output_text"] = reporter.get_output_text()
        return output
    except Exception:
        output = {}
        output['errors'] = [traceback.format_exc()]
        logger.error("__run_parser %s %s" % (name, traceback.format_exc()))
        return output

if __name__ == '__main__':
    run(app, server='auto', host='localhost', port=8080)
else:
    application = app
