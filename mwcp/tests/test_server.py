import base64
import io
import json
import logging
import textwrap

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


def _get_expected_results(legacy: bool):
    output_text = textwrap.dedent("""\
        ----- File: 33fb2ffd28461fa230b730f0d9db81c9.bin -----
        Field         Value
        ------------  ----------------------------------------------------------------
        Parser        foo
        File Path
        Description   Foo
        Architecture
        MD5           33fb2ffd28461fa230b730f0d9db81c9
        SHA1          8eb231a85a9445902571ef2ca8e3f64ec085519d
        SHA256        cc4fafa4c90b4e4c08ade61acfa63add6a3fc31aa58d3f217eb199f557512e2a
        Compile Time

        ---- Network ----
        Url               Protocol    Address
        ----------------  ----------  ---------
        http://127.0.0.1  http        127.0.0.1

        ---- Socket ----
        Address
        ---------
        127.0.0.1

        ---- URL ----
        Url               Protocol
        ----------------  ----------
        http://127.0.0.1  http

        ---- Residual Files ----
        Filename           Description          Derivation                  MD5                               Arch    Compile Time
        -----------------  -------------------  --------------------------  --------------------------------  ------  --------------
        fooconfigtest.txt  example output file  extracted and decompressed  5eb63bbbe01eeed093cb22bb8f5acdc3

        ----- File Tree -----
        <33fb2ffd28461fa230b730f0d9db81c9.bin (33fb2ffd28461fa230b730f0d9db81c9) : Foo>
        └── <fooconfigtest.txt (5eb63bbbe01eeed093cb22bb8f5acdc3) : example output file>

    """)

    if legacy:
        return {
            'address': ['127.0.0.1'],
            'output_text': output_text,
            'outputfile': [
                [
                    'fooconfigtest.txt',
                    'example output file',
                    '5eb63bbbe01eeed093cb22bb8f5acdc3',
                    'aGVsbG8gd29ybGQ='
                ]
            ],
            'url': ['http://127.0.0.1']
        }

    else:
        return {
            "type": "report",
            "tags": [],
            "mwcp_version": mwcp.__version__,
            "input_file": {
                "type": "file",
                "tags": [],
                "name": "33fb2ffd28461fa230b730f0d9db81c9.bin",
                "description": "Foo",
                "architecture": None,
                "md5": "33fb2ffd28461fa230b730f0d9db81c9",
                "sha1": "8eb231a85a9445902571ef2ca8e3f64ec085519d",
                "sha256": "cc4fafa4c90b4e4c08ade61acfa63add6a3fc31aa58d3f217eb199f557512e2a",
                "compile_time": None,
                "file_path": None,
                "data": "VGhpcyBpcyBhIHRlc3QgZmlsZSEK",
                "derivation": None,
            },
            "parser": "foo",
            "recursive": True,
            "external_knowledge": {},
            "metadata": [
                {
                    'path': None,
                    'protocol': 'http',
                    'query': None,
                    'tags': [],
                    'type': 'url',
                    'url': 'http://127.0.0.1'},
                {
                    'credential': None,
                    'socket': {
                        'address': '127.0.0.1',
                        'listen': None,
                        'network_protocol': None,
                        'port': None,
                        'tags': [],
                        'type': 'socket'
                    },
                    'tags': [],
                    'type': 'network',
                    'url': {
                        'path': None,
                        'protocol': 'http',
                        'query': None,
                        'tags': [],
                        'type': 'url',
                        'url': 'http://127.0.0.1'},
                },
                {
                    'address': '127.0.0.1',
                    'listen': None,
                    'network_protocol': None,
                    'port': None,
                    'tags': [],
                    'type': 'socket'
                },
                {
                    "type": "file",
                    "tags": [],
                    "name": "fooconfigtest.txt",
                    "description": "example output file",
                    "md5": "5eb63bbbe01eeed093cb22bb8f5acdc3",
                    "sha1": "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
                    "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                    "architecture": None,
                    "compile_time": None,
                    "data": "aGVsbG8gd29ybGQ=",
                    "file_path": None,
                    "derivation": "extracted and decompressed",
                }
            ],
            "output_text": output_text,
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


@pytest.mark.xfail
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


@pytest.mark.parametrize("url,options,legacy", [
    ("/run_parser", {"parser": "foo"}, True),
    ("/run_parser", {"parser": "foo", "legacy": "False"}, False),
    ("/run_parser/foo", {}, True),
    ("/run_parser/foo?legacy=False", {}, False),
    ("/run_parser?parser=foo", {}, True),
    ("/run_parser?parser=foo&legacy=False", {}, False),
])
def test_run_parser(client, make_test_buffer, url, options, legacy):
    """
    Tests running a parser through a variety of different means.
    """
    expected_results = _get_expected_results(legacy)
    options = {
        "data": (make_test_buffer(), "test.file"),
        "include_logs": "False",
        **options
    }
    rv = client.post(url, data=options)
    results = rv.json
    print(results["output_text"])
    print(json.dumps(results, indent=4))
    # Remove logs and errors entries so make testing easier.
    results.pop("errors", None)
    results.pop("debug", None)
    results.pop("logs", None)
    assert results == expected_results


def test_external_strings_report(datadir, client, make_test_buffer):
    """
    Tests creating an external strings report.
    """
    mwcp.register_parser_directory(str(datadir), source_name="test")

    options = {
        "data": (make_test_buffer(), "test.file"),
        "external_strings": True,
        "legacy": False,
    }
    rv = client.post("/run_parser/DecodedStringTestParser.Implant", data=options)
    results = rv.json
    print(results["output_text"])
    print(json.dumps(results, indent=4))
    files = [element for element in results["metadata"] if element["type"] == "file"]

    assert len(files) == 2
    assert all(file["description"] == "Decoded Strings" for file in files)

    strings_json = files[0]
    assert strings_json["name"].endswith("_strings.json")
    string_report = json.loads(base64.b64decode(strings_json["data"]))
    assert [string["value"] for string in string_report["strings"]] == ["string A", "string B"]
    enc_key = string_report["strings"][1]["encryption_key"]
    assert enc_key
    assert base64.b64decode(enc_key["key"]) == b"\xde\xad\xbe\xef"

    strings_txt = files[1]
    strings = base64.b64decode(strings_txt["data"])
    assert strings == b"string A\nstring B"



def test_run_parser_errors(client, make_test_buffer):
    # No file
    rv = client.post("/run_parser", data={"parser": "foo"})

    assert rv.status_code == 400
    print(rv.json)
    # ignore output_text since matching everything else covers it and this avoids worrying about formatting
    result = rv.json
    del result["output_text"]
    assert {"errors": ["[!] No input file provided"], "debug": ["[!] No input file provided"]} == result

    # No file and no parser
    rv = client.post("/run_parser")

    assert rv.status_code == 400
    print(rv.json)
    # ignore output_text since matching everything else covers it and this avoids worrying about formatting
    result = rv.json
    del result["output_text"]
    assert {"errors": ["[!] No input file provided"], "debug": ["[!] No input file provided"]} == result


@pytest.mark.parametrize("legacy", [True, False])
def test_highlight_results(client, make_test_buffer, legacy):
    import pygments.lexer
    from pygments.formatters.html import HtmlFormatter
    from pygments.lexers.special import TextLexer

    options = {
        "parser": "foo",
        "highlight": True,
        "output": "text",
        "data": (make_test_buffer(), "test.file"),
        "include_logs": False,
        "legacy": legacy,
    }
    rv = client.post("/run_parser", data=options)

    assert rv.status_code == 200

    fmt = HtmlFormatter()
    expected_results = _get_expected_results(legacy)
    plain_text_html = pygments.highlight(expected_results['output_text'], TextLexer(), fmt).encode()
    assert plain_text_html in rv.data


def test_params(client, make_test_buffer):
    rv = client.post("/run_parser", data={
        "parser": "foo",
        "param": ["key:secret", "hello:4"],
        "data": (make_test_buffer(), "test.file"),
        "legacy": False,
    })
    assert rv.status_code == 200
    assert rv.json["external_knowledge"] == {"key": "secret", "hello": 4}


@pytest.mark.parametrize("legacy", [True, False])
def test_zip_download(client, make_test_buffer, legacy):
    """Test results ZIP functionality"""
    import zipfile
    import json
    import posixpath
    import base64

    options = {
        "parser": "foo",
        "output": "zip",
        "data": (make_test_buffer(), "test.file"),
        "include_logs": False,
        "legacy": legacy,
    }
    rv = client.post("/run_parser", data=options)

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

    expected_results = _get_expected_results(legacy)
    if legacy:
        expected_residual_files = expected_results.pop("outputfile", [])
    # Residual files are removed from metadata for zip download results.
    # TODO: should we just be nulling out the data instead?
    else:
        expected_residual_files = [
            element
            for element in expected_results["metadata"]
            if element["type"] == "file"
        ]
        expected_results["metadata"] = [
            element
            for element in expected_results["metadata"]
            if element["type"] != "file"
        ]

    results_txt = zip_file.read("results.txt").decode("unicode_escape")
    expected_output_text = expected_results.pop("output_text", "")
    assert results_txt == expected_output_text

    expected_json = expected_results.copy()
    results_json = zip_file.read("results.json").decode()
    # "logs" and "errors" fields are still provided even if include_logs is False.
    if not legacy:
        expected_json["logs"] = []
        expected_json["errors"] = []
    assert json.loads(results_json) == expected_json

    for output_file in expected_residual_files:
        if legacy:
            filename = output_file[0]
            data = output_file[3]
        else:
            filename = output_file["name"]
            data = output_file["data"]
        data = base64.b64decode(data)
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
