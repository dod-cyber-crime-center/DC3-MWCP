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
from typing import Tuple, Union, Optional

import flask
import mwcp
import mwcp.parsers
import pygments
import pygments.formatter
import pygments.lexer
from pygments.formatters.html import HtmlFormatter
from pygments.lexers.data import JsonLexer
from pygments.lexers.special import TextLexer
from werkzeug.utils import secure_filename

from mwcp.report import Report

bp = flask.Blueprint("mwcp", __name__)
YARA_MATCH = "-- YARA Match --"


def init_app(app):
    """Initialize the Flask application and MWCP"""
    # Initialize MWCP
    mwcp.config.load(os.getenv("MWCP_CONFIG", None), production=True)
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
    flask.current_app.logger.warning(dep_warning)
    output.setdefault("errors", []).append(dep_warning)

    datafile = flask.request.files.get("data")
    if datafile:
        data = datafile.read()
        flask.current_app.logger.info(
            "run_parsers %s %s %s",
            parsers,
            datafile.filename,
            hashlib.md5(data).hexdigest(),
        )
        for parser in parsers.split("/"):
            if parser:
                # TODO: Determine if it should be possible to specify the output format and have file data not be included
                report = _run_parser(parser, data)
                output[parser] = _format_report(report)
    else:
        output.setdefault("errors", []).append("No input file provided")
        flask.current_app.logger.error("run_parsers %s no input file", parsers)
    return flask.jsonify(output)


@bp.route("/parsers")
def parsers_list():
    """
    List of configured parsers with names, sources, authors, and descriptions.

    Normally an HTML table, but if `application/json` is the best mimetype set
    in the `Accept` header, the response will be in JSON.
    """
    name_filter = flask.request.args.get("name", type=str)
    source_filter = flask.request.args.get("source", type=str)

    headers = ("Name", "Source", "Author", "Description")
    parsers_info = mwcp.get_parser_descriptions(name=name_filter, source=source_filter)

    if flask.request.accept_mimetypes.best == "application/json":
        return flask.jsonify(
            {"parsers": [parser_info._asdict() for parser_info in parsers_info]}
        )

    flask.g.title = "Parsers"
    return flask.render_template("parsers.html", headers=headers, parsers=parsers_info)


@bp.route("/upload")
def upload():
    """Upload page"""
    flask.g.title = "Upload"
    parsers = [parser.name for parser in mwcp.get_parser_descriptions()]
    # Add yara match option if user has setup a yara repo.
    if mwcp.config.get("YARA_REPO"):
        parsers = [YARA_MATCH, *parsers]
    return flask.render_template("upload.html", parsers=parsers)


@bp.route("/descriptions")
def descriptions():
    """
    List descriptions of parser modules.
    This is for backwards compatibility purposes.
    Always a JSON response.
    """
    return flask.jsonify(
        [
            (parser_info.name, parser_info.author, parser_info.description)
            for parser_info in mwcp.get_parser_descriptions()
        ]
    )


@bp.route("/schema.json")
def schema():
    """
    Provides JSON schema for report output.
    """
    return flask.jsonify(mwcp.schema())


@bp.route("/logs")
def logs():
    """
    Endpoint for all logs from the current session.

    Always a JSON response.

    This can be disabled with the ``DISABLE_LOGS_ENDPOINT`` key
    in the app config.
    """
    if flask.current_app.config.get("DISABLE_LOGS_ENDPOINT"):
        return (
            flask.jsonify({"errors": ["Logs endpoint has been disabled by configuration"]}),
            403,
        )

    return flask.jsonify({"errors": ["Logs endpoint is no longer supported."]})


@bp.route("/")
def default():
    """
    Homepage endpoint.
    """
    return flask.render_template("base.html")


class RequestFilter(logging.Filter):
    """
    Filter to lock a handler to a specific request.

    This is required for multi-threading the server.
    """

    def __init__(self, request):
        super().__init__("request_filter")
        # The `request` is usually a proxy to the real request
        if hasattr(request, "_get_current_object"):
            request = request._get_current_object()
        self._request = request

    def filter(self, record):
        # Ensure the proxied request is our locked request
        # And the record is created in a request context to begin with
        if not flask.has_request_context():
            return False
        return flask.request == self._request


def _get_option(name, default=False) -> bool:
    """Obtains flask request boolean option."""
    option = flask.request.values.get(name, default=default)
    if isinstance(option, str):
        option = option.lower() == "true"
    return option


def _legacy():
    """Whether we are using legacy or new metadata schema."""
    return _get_option("legacy", True)


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

    return flask.render_template(
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
    legacy = _legacy()

    if legacy:
        encoded_files = parser_results.pop("outputfile", [])
    else:
        encoded_files = []
        metadata_list = list(parser_results["metadata"])
        for element in metadata_list:
            if element["type"] == "file":
                encoded_files.append(element)
                parser_results["metadata"].remove(element)

    output_text = parser_results.pop("output_text", "")

    zf = zipfile.ZipFile(
        zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
    )
    with zf:
        for file_obj in encoded_files:
            if legacy:
                filename = file_obj[0]
                base64_data = file_obj[3]
            else:
                filename = file_obj["name"]
                base64_data = file_obj["data"]
            file_data = base64.b64decode(base64_data)
            zf.writestr(os.path.join("files", filename), file_data)

        zf.writestr("results.json", json.dumps(parser_results, indent=2))

        if not isinstance(output_text, bytes):
            output_text = output_text.encode("ascii", "backslashreplace")
        zf.writestr("results.txt", output_text)

    zip_buf.seek(0)
    return zip_buf


def _build_parser_response(parser=None) -> Union[flask.Response, Tuple[flask.Response, int]]:
    """
    Build the response object for a parser request.
    This function handles the form fields and/or URL parameters and
    returns an appropriate response object. This can be overridden
    (e.g. by specific endpoints) as a parameter.

    :param str parser: The name of the parser to run. Pulled from `parser`
        URL parameter or form field if not specified.
    :return: Flask response object with optional status code.
    """
    output = flask.request.values.get("output", "json")
    output = output.lower()
    if output not in ("json", "text", "zip", "stix"):
        flask.current_app.logger.warning(f"Unknown output type received: '{output}'")
        output = "json"
    highlight = flask.request.values.get("highlight")

    if not highlight:
        json_response = flask.jsonify
    else:
        json_response = _highlight

    report, response_code = _run_parser_request(parser)

    if response_code != 200:
        parser_results = _format_report(report)
        return json_response(parser_results), response_code

    if output == "stix":
        parser_results = report.as_stix()
        if highlight:
            return json_response(parser_results)
        else:
            return json_response(json.loads(parser_results))
    else:
        parser_results = _format_report(report)

    # A ZIP returns both JSON and plain text, and has no highlighting
    if output == "zip":
        filename = secure_filename(flask.request.files.get("data").filename)
        zip_buf = _build_zip(parser_results)
        return flask.send_file(
            zip_buf, "application/zip", True, f"{filename}_mwcp_output.zip"
        )

    if highlight:
        output_text = parser_results.pop("output_text", "")
        if output == "text":
            return _highlight(output_text, False)

    return json_response(parser_results)


def _format_report(report: Report):
    if _legacy():
        output = report.as_dict_legacy()
    else:
        output = report.as_json_dict()

    output["output_text"] = report.as_text()

    return output


def _parse_parameters(params) -> dict:
    """
    Parses the results from the --parameter option in the `parse` and `test` command.
    Returns a knowledge_base dictionary.
    """
    knowledge_base = {}
    for entry in params:
        key, found, value = entry.partition(":")
        if not found:
            # How we raise error?
            raise ValueError(f"Missing ':' in parameter: '{entry}'")
        if value.casefold() == "true":
            value = True
        elif value.casefold() == "false":
            value = False
        else:
            try:
                value = int(value)
            except ValueError:
                pass
        if key in knowledge_base:
            raise ValueError(f"'{key}' parameter defined twice.")
        knowledge_base[key] = value
    return knowledge_base


def _run_parser_request(parser=None, upload_name="data") -> (Report, int):
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
        Can be blank to use YARA matching.
    :param str upload_name: The name of the field of the uploaded sample
    :return: The results from the parser run and/or errors and an appropriate status code
    :rtype: (Report, int)
    """
    errors = []

    parser = parser or flask.request.values.get("parser")

    uploaded_file = flask.request.files.get(upload_name)
    if not uploaded_file:
        flask.current_app.logger.error(
            f"Error running parser '{parser or '-'}' no input file"
        )
        errors.append("No input file provided")

    # Client errors
    if errors:
        report = Report()
        for error in errors:
            flask.current_app.logger.error(error)
        return report, 400

    data = uploaded_file.read()
    flask.current_app.logger.info(
        "Request for parser '%s' on '%s' %s",
        parser,
        secure_filename(uploaded_file.filename),
        hashlib.md5(data).hexdigest(),
    )
    if parser == YARA_MATCH:
        parser = None
    report = _run_parser(parser, data)

    return report, 200


def _run_parser(parser_name: Optional[str], data: bytes) -> Report:
    """
    Run an MWCP parser on given data.

    Logs to a list handler that is locked to the current request.

    :param str parser_name: Name of the parser to run (or None for YARA match)
    :param bytes data: Data to run parser on
    :return: Output from the reporter
    :rtype: Report
    """
    report = Report()
    try:
        params = flask.request.values.getlist("param") + flask.request.values.getlist("parameter")
        knowledge_base = _parse_parameters(params)

        include_logs = _get_option("include_logs", True)
        report = mwcp.run(
            parser_name,
            data=data,
            recursive=_get_option("recursive", True),
            include_logs=include_logs,
            include_file_data=not _get_option("no_file_data", False),
            log_filter=RequestFilter(flask.request) if include_logs else None,
            external_strings_report=_get_option("external_strings", False),
            knowledge_base=knowledge_base
        )

    except Exception as e:
        if flask.has_app_context():
            flask.current_app.logger.error(
                "Error running parser '%s': %s", parser_name, str(e)
            )
    finally:
        return report
