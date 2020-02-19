import io
import logging

import pytest

import mwcp
from mwcp.tools.server import create_app


@pytest.fixture(scope='module')
def client():
    app = create_app()
    with app.test_client() as client:
        yield client


@pytest.fixture
def parsers():
    yield mwcp.get_parser_descriptions()


@pytest.fixture
def expected_results():
    return {
        u"address": [u"127.0.0.1"],
        u"debug": [],
        u"output_text": (
            u"\n----Standard Metadata----\n\n"
            u"url                  http://127.0.0.1\n"
            u"address              127.0.0.1\n\n"
            u"----Debug----\n\n\n"
            u"----Output Files----\n\n"
            u"fooconfigtest.txt    example output file\n"
            u"                     5eb63bbbe01eeed093cb22bb8f5acdc3\n"
        ),
        u"outputfile": [
            [
                u"fooconfigtest.txt",
                u"example output file",
                u"5eb63bbbe01eeed093cb22bb8f5acdc3",
                u"aGVsbG8gd29ybGQ=",
            ]
        ],
        u"url": [u"http://127.0.0.1"],
    }


@pytest.fixture(scope="module")
def make_test_buffer():
    # The client closes the file-object when it's completed its request
    # so we need to be able to generate a new one when needed
    def _make_test_buffer():
        return io.BytesIO(b"This is a test file!\n")

    return _make_test_buffer


def test_homepage(client):
    """Test the homepage is accessible"""
    rv = client.get("/")
    assert rv.status_code == 200
    assert b"DC3-MWCP Service" in rv.data


def test_menu(client):
    """Test menu items can be added"""
    # Menu links can be created via adding to the config
    client.application.config["MENU_LINKS"].append(
        {"name": "Example", "url": "http://example.com"}
    )
    rv = client.get("/")
    assert b'<li><a href="/">Home</a></li>' in rv.data
    assert b'<li><a href="http://example.com">Example</a></li>' in rv.data


def test_log_endpoint(client):
    from mwcp.utils import logutil

    rv = client.get("/logs")

    assert {"errors": ["No 'mwcp_server' handler defined on root logger."]} == rv.json
    assert rv.status_code == 500

    list_handler = logutil.ListHandler()
    list_handler.name = "mwcp_server"
    logging.root.addHandler(list_handler)

    rv = client.get("/logs")
    assert rv.status_code == 200
    assert isinstance(rv.json, dict)
    assert "logs" in rv.json
    logging.root.removeHandler(list_handler)

    client.application.config["DISABLE_LOGS_ENDPOINT"] = True
    rv = client.get("/logs")
    assert rv.status_code == 403
    assert {"errors": ["Logs endpoint has been disabled by configuration"]} == rv.json


def test_run_parser_fields(client, expected_results, make_test_buffer):
    """Test parser selection by form field"""
    rv = client.post(
        "/run_parser", data={"parser": "foo", "data": (make_test_buffer(), "test.file")}
    )
    assert rv.json == expected_results


def test_run_parser_resource(client, expected_results, make_test_buffer):
    """Test parser selection based on resource name"""
    rv = client.post(
        "/run_parser/foo", data={"data": (make_test_buffer(), "test.file")}
    )
    assert rv.json == expected_results


def test_run_parser_url_param(client, expected_results, make_test_buffer):
    """Test parser selection by URL parameter"""
    rv = client.post(
        "/run_parser?parser=foo", data={"data": (make_test_buffer(), "test.file")}
    )
    assert rv.json == expected_results


def test_run_parser_errors(client, make_test_buffer):
    # No parser
    rv = client.post("/run_parser", data={"data": (make_test_buffer(), "test.file")})

    assert rv.status_code == 400
    assert {"errors": ["No parser specified"]} == rv.json

    # No file
    rv = client.post("/run_parser", data={"parser": "foo"})

    assert rv.status_code == 400
    assert {"errors": ["No input file provided"]} == rv.json


def test_highlight_results(client, expected_results, make_test_buffer):
    import pygments.lexer
    from pygments.formatters.html import HtmlFormatter
    from pygments.lexers.special import TextLexer

    rv = client.post(
        "/run_parser",
        data={
            "parser": "foo",
            "highlight": "True",
            "output": "text",
            "data": (make_test_buffer(), "test.file"),
        },
    )

    assert rv.status_code == 200

    fmt = HtmlFormatter()
    plain_text_html = pygments.highlight(expected_results['output_text'], TextLexer(), fmt).encode()
    assert plain_text_html in rv.data


def test_zip_download(client, make_test_buffer, expected_results):
    """Test results ZIP functionality"""
    import zipfile
    import json
    import posixpath
    import base64

    rv = client.post(
        "/run_parser",
        data={
            "parser": "foo",
            "output": "zip",
            "data": (make_test_buffer(), "test.file"),
        },
    )

    assert (
            rv.headers.get("Content-Disposition")
            == "attachment; filename=test.file_mwcp_output.zip"
    )

    zip_file = zipfile.ZipFile(io.BytesIO(rv.data))
    assert zip_file
    assert set(zip_file.namelist()) == {
        "results.txt",
        "results.json",
        "files/fooconfigtest.txt",
    }

    results_txt = zip_file.read("results.txt")
    assert results_txt == expected_results["output_text"].encode()

    expected_json = expected_results.copy()
    expected_json.pop("output_text")
    expected_json.pop("outputfile")
    results_json = zip_file.read("results.json").decode()
    assert expected_json == json.loads(results_json)

    for output_file in expected_results["outputfile"]:
        filename = output_file[0]
        data = base64.b64decode(output_file[3])
        zip_path = posixpath.join("files", filename)

        assert zip_file.read(zip_path) == data


def test_upload_options(client, parsers):
    """Test the upload page lists all parsers"""
    rv = client.get("/upload")

    option_str = '<option value="{name}">{name}</option>'

    for parser in parsers:
        assert option_str.format(name=parser.name).encode() in rv.data


def test_parsers(client, parsers):
    """Test the HTML parsers page lists the parsers"""
    import flask

    rv = client.get("/parsers")

    example_row = """\
            <tr>
                
                    <td>{name}</td>
                
                    <td>{source}</td>
                
                    <td>{author}</td>
                
                    <td>{description}</td>
                
            </tr>"""

    for parser in parsers:
        # Each string must be escaped, this is esp. for descriptions
        escaped_info = {k: flask.escape(v) for k, v in parser._asdict().items()}
        row = example_row.format(**escaped_info).encode()
        assert row in rv.data


def test_parsers_json(client, parsers):
    """Test the JSON parsers response lists all parsers"""
    rv = client.get("/parsers", headers={"Accept": "application/json"})

    assert rv.content_type == "application/json"
    assert isinstance(rv.json, dict)
    assert "parsers" in rv.json

    parsers_json = rv.json["parsers"]

    assert len(parsers_json) == len(parsers)

    for parser in parsers:
        assert parser._asdict() in parsers_json


def test_descriptions(client, parsers):
    """Test the legacy descriptions endpoint lists all parsers"""
    rv = client.get("/descriptions")
    parser_descriptions = rv.json
    assert parser_descriptions
    assert isinstance(parser_descriptions, list)
    assert len(parser_descriptions) == len(parsers)

    for idx, parser in enumerate(parsers):
        assert parser_descriptions[idx] == [
            parser.name,
            parser.author,
            parser.description,
        ]
