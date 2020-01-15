#!/usr/bin/env python

"""
DC3-MWCP server--simple REST API using the Flask framework.
"""
from __future__ import absolute_import, print_function

import base64
import hashlib
import io
import json
import logging
import os
import zipfile
from copy import copy

import flask as f
import mwcp
import mwcp.parsers
import pygments
import pygments.formatter
import pygments.lexer
from mwcp.utils import logutil
from pygments.formatters.html import HtmlFormatter
from pygments.lexers.data import JsonLexer
from pygments.lexers.special import TextLexer
from werkzeug.utils import secure_filename

bp = f.Blueprint("mwcp", __name__)


def init_app(app):
    """Initialize the Flask application and MWCP"""
    # Initialize MWCP
    mwcp.config.load(os.getenv("MWCP_CONFIG", None))
    mwcp.register_entry_points()


@bp.route("/run_parser/<parser>", methods=["POST"], strict_slashes=False)
@bp.route("/run_parser", methods=["POST"], strict_slashes=False)
def run_parser(parser=None):
    """
    Execute a parser and return the results.

    The file must be uploaded in the field "data".

    The parser must be specified in the `parser` field, parameter, or in the resource name.

    The field `output` may be set to `zip` to download a ZIP
    file of the results and extracted components. By default the
    output is JSON.

    The field  or parameter `highlight` may also be set to return
    a formatted HTML page with the results.

    All fields (except `data`) may be set as URL parameters as well.

    :param str parser: The name of the parser to run
    """
    return _build_parser_response(parser)


@bp.route("/run_parsers/<path:parsers>", methods=["POST"])
def run_parsers(parsers):
    """
    Execute multiple parsers on the same input file.

    NOTE: The way this function works may change in a future version

    :param str parsers: List of parsers to run
    """
    output = {}

    dep_warning = (
        "Running multiple parsers in a single request will be changed future version."
    )
    f.current_app.logger.warning(dep_warning)
    output.setdefault("errors", []).append(dep_warning)

    datafile = f.request.files.get("data")
    if datafile:
        data = datafile.read()
        f.current_app.logger.info(
            "run_parsers %s %s %s",
            parsers,
            datafile.filename,
            hashlib.md5(data).hexdigest(),
        )
        for parser in parsers.split("/"):
            if parser:
                output[parser] = _run_parser(parser, data=data)
    else:
        output.setdefault("errors", []).append("No input file provided")
        f.current_app.logger.error("run_parsers %s no input file", parsers)
    return f.jsonify(output)


@bp.route("/parsers")
def parsers_list():
    """
    List of configured parsers with names, sources, authors, and descriptions.

    Normally an HTML table, but if `application/json` is the best mimetype set
    in the `Accept` header, the response will be in JSON.
    """
    name_filter = f.request.args.get("name", type=str)
    source_filter = f.request.args.get("source", type=str)

    headers = ("Name", "Source", "Author", "Description")
    parsers_info = mwcp.get_parser_descriptions(name=name_filter, source=source_filter)

    if f.request.accept_mimetypes.best == "application/json":
        return f.jsonify(
            {"parsers": [parser_info._asdict() for parser_info in parsers_info]}
        )

    f.g.title = "Parsers"
    return f.render_template("parsers.html", headers=headers, parsers=parsers_info)


@bp.route("/upload")
def upload():
    """Upload page"""
    f.g.title = "Upload"
    parsers_info = mwcp.get_parser_descriptions()
    return f.render_template("upload.html", parsers=parsers_info)


@bp.route("/descriptions")
def descriptions():
    """
    List descriptions of parser modules.
    This is for backwards compatibility purposes.
    Always a JSON response.
    """
    return f.jsonify(
        [
            (parser_info.name, parser_info.author, parser_info.description)
            for parser_info in mwcp.get_parser_descriptions()
        ]
    )


@bp.route("/logs")
def logs():
    """
    Endpoint for all logs from the current session.

    Always a JSON response.

    This can be disabled with the ``DISABLE_LOGS_ENDPOINT`` key
    in the app config.
    """
    if f.current_app.config.get("DISABLE_LOGS_ENDPOINT"):
        return (
            f.jsonify({"errors": ["Logs endpoint has been disabled by configuration"]}),
            403,
        )

    handler = _get_existing_handler()
    if not handler:
        return (
            f.jsonify({"errors": ["No 'mwcp_server' handler defined on root logger."]}),
            500,
        )
    return f.jsonify({"logs": handler.messages})


@bp.route("/")
def default():
    """
    Homepage endpoint.
    """
    return f.render_template("base.html")


class RequestFilter(object):
    """
    Filter to lock a handler to a specific request.

    This is required for multi-threading the server.
    """

    def __init__(self, request=None):
        # The `request` is usually a proxy to the real request
        if hasattr(request, "_get_current_object"):
            request = request._get_current_object()

        self._request = request

    def filter(self, record):
        # Ensure the proxied request is our locked request
        # And the record is created in a request context to begin with
        if not f.has_request_context():
            return False
        return f.request == self._request


def _get_existing_handler(handler_name="mwcp_server"):
    """
    Retrieve an existing ListHandler by name from the root logger.
    """
    for handler in logging.root.handlers:
        if handler.name == handler_name and isinstance(handler, logutil.ListHandler):
            return handler


def _get_log_handler(handler_name="mwcp_server"):
    """
    Get the handler for the parser running.

    Attempts to get 'mwcp_server' handler from the root logger, and create
    a clean copy, keeping any formatters and level settings.

    If the handler does not exist, create a default handler.
    """
    handler = _get_existing_handler(handler_name)
    if handler:
        if isinstance(handler, logutil.ListHandler):
            new_handler = copy(handler)
            new_handler.clear()
            return new_handler
        f.current_app.logger.warning(
            "Root handler '{}' is not a ListHandler.".format(handler_name)
        )

    f.current_app.logger.info(
        "No 'mwcp_server' handler defined on root logger. Using default."
    )
    list_handler = logutil.ListHandler()
    list_handler.setFormatter(
        logging.Formatter("[%(level_char)s] (%(name)s): %(message)s")
    )
    list_handler.addFilter(logutil.LevelCharFilter())

    return list_handler


def _highlight(data, is_json=True):
    """
    Render an HTML page with a highlighted JSON string or plain text.

    :param data: Data to highlight, should be a string or JSON-able object
    :param is_json: If the data is a JSON string or can be converted into such
    :return: Response object with rendered template with highlighted data
    """
    if is_json and not isinstance(data, (str, bytes)):
        data = json.dumps(data, indent=2)

    # Pygments highlighting
    lexer = JsonLexer() if is_json else TextLexer()
    formatter = HtmlFormatter()
    highlight = pygments.highlight(data, lexer, formatter)

    return f.render_template(
        "results.html", highlight=highlight, extra_css=formatter.get_style_defs()
    )


def _build_zip(parser_results):
    """
    Build a ZIP file containing the results and artifacts of a parser run.

    Expects the **full** parser results, including ``output_text`` and ``outputfile`` keys.

    The folder structure looks like this:

    .. code_block::

        mwcp_server.zip
        |
        |-results.json
        |-results.txt (this is ``output_text``)
        |
        |---files
            |
            |- ExtractedComponent1.exe
            |- ExtractedComponent2.dll


    :param parser_results:
    :return: A BytesIO buffer containing a ZIP file
    :rtype: io.BytesIO
    """
    zip_buf = io.BytesIO()

    encoded_files = parser_results.pop("outputfile", [])
    output_text = parser_results.pop("output_text", "")

    zf = zipfile.ZipFile(
        zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
    )
    with zf:
        for file_obj in encoded_files:
            filename = file_obj[0]
            base64_data = file_obj[3]
            file_data = base64.b64decode(base64_data)
            zf.writestr(os.path.join("files", filename), file_data)

        zf.writestr("results.json", json.dumps(parser_results, indent=2))

        if not isinstance(output_text, bytes):
            output_text = output_text.encode("ascii", "backslashreplace")
        zf.writestr("results.txt", output_text)

    zip_buf.seek(0)
    return zip_buf


def _build_parser_response(parser=None, **kwargs):
    """
    Build the response object for a parser request.
    This function handles the form fields and/or URL parameters and
    returns an appropriate response object. This can be overridden
    (e.g. by specific endpoints) as a parameter.

    :param str parser: The name of the parser to run. Pulled from `parser`
        URL parameter or form field if not specified.
    :return: Flask response object
    """
    output = kwargs.get("output", "") or f.request.values.get("output", "json")
    output = output.lower()
    if output not in ("json", "text", "zip"):
        f.current_app.logger.warning(
            "Unknown output type received: '{}'".format(output)
        )
        output = "json"
    highlight = kwargs.get("highlight") or f.request.values.get("highlight")

    if not highlight:
        json_response = f.jsonify
    else:
        json_response = _highlight

    parser_results, response_code = _run_parser_request(parser)

    if response_code != 200:
        return json_response(parser_results), response_code

    # A ZIP returns both JSON and plain text, and has no highlighting
    if output == "zip":
        filename = secure_filename(f.request.files.get("data").filename)
        zip_buf = _build_zip(parser_results)
        return f.send_file(
            zip_buf, "application/zip", True, "{}_mwcp_output.zip".format(filename)
        )

    if highlight:
        parser_results.pop("outputfile", [])
        output_text = parser_results.pop("output_text", "")
        if output == "text":
            return _highlight(output_text, False)

    return json_response(parser_results)


def _run_parser_request(parser=None, upload_name="data", output_text=True):
    """
    Run a parser based on the data in the current request.

    This function handles getting the file from the form field, as well as
    the parser from either a form field or url parameter if not explicitly set.

    The results from the parser run (a ``dict``) is returned as well as an
    appropriate HTTP status code. Specifically, a 2XX if the parser ran
    successfully, a 4XX if there is a problem with the request (e.g no
    file) or a 5XX if there was a problem with running the parser.

    :param str parser: The name of the parser to run. Pulled from `parser`
        URL parameter or form field if not specified.
    :param str upload_name: The name of the field of the uploaded sample
    :param bool output_text: If the `output_text` key should be included in the output
    :return: The results from the parser run and/or errors and an appropriate status code
    :rtype: (dict, int)
    """
    errors = []

    parser = parser or f.request.values.get("parser")
    if not parser:
        errors.append("No parser specified")

    uploaded_file = f.request.files.get(upload_name)
    if not uploaded_file:
        f.current_app.logger.error(
            "Error running parser '{}' no input file".format(parser)
        )
        errors.append("No input file provided")

    # Client errors
    if errors:
        return {"errors": errors}, 400

    data = uploaded_file.read()
    f.current_app.logger.info(
        "Request for parser '%s' on '%s' %s",
        parser,
        secure_filename(uploaded_file.filename),
        hashlib.md5(data).hexdigest(),
    )
    parser_results = _run_parser(parser, data=data, append_output_text=output_text)

    return parser_results, 200


def _run_parser(name, data=b"", append_output_text=True):
    """
    Run an MWCP parser on given data.

    Logs to a list handler that is locked to the current request.

    :param str name: Name of the parser to run
    :param bytes data: Data to run parser on
    :param bool append_output_text: If the text that would otherwise be printed is
        added to the output data
    :return: Output from the reporter
    :rtype: dict
    """
    output = {}
    mwcp_logger = logging.getLogger("mwcp")
    list_handler = _get_log_handler()
    try:
        # Record only records created in the context of this request
        list_handler.addFilter(RequestFilter(request=f.request))
        mwcp_logger.addHandler(list_handler)

        reporter = mwcp.Reporter(base64_output_files=True)
        reporter.run_parser(name, data=data)
        output = reporter.metadata

        output["debug"] = [msg for msg in list_handler.messages]

        if append_output_text:
            output["output_text"] = reporter.get_output_text()
    except Exception as e:
        output = {"errors": [str(e)]}
        if f.has_app_context():
            f.current_app.logger.exception(
                "Error running parser '%s': %s", name, str(e)
            )
    finally:
        mwcp_logger.removeHandler(list_handler)
        return output
