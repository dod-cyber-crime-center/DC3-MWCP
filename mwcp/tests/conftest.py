import difflib
from typing import List

import pytest

import mwcp
from mwcp import metadata
from mwcp.metadata import Metadata


def pytest_configure(config):
    """
    Registers custom markers.
    """
    config.addinivalue_line(
        "markers", "parsers: mark to only test parsers"
    )


def pytest_addoption(parser):
    """
    Creates CLI options for setting MWCP configuration.
    """
    parser.addoption(
        "--testcase-dir", action="store",
        help="Directory containing JSON test case files for parser tests."
    )
    parser.addoption(
        "--malware-repo", action="store",
        help="Directory containing malware samples for parser tests."
    )
    parser.addoption(
        "--yara-repo", action="store",
        help="Directory containing YARA rules used for recursive matching."
    )
    parser.addoption(
        "--full-diff", action="store_true",
        help="Whether to disable the custom unified diff view and instead use pytest's default full diff."
    )


def pytest_make_parametrize_id(config, val, argname):
    """
    Hook id creation to convert legacy name to something more helpful than just "True"/"False".
    """
    if "legacy" in argname:
        return "legacy" if val else "new"


def pytest_assertrepr_compare(config, op, left, right):
    """
    Hooks assertion message creation in order to display a more condensed unified diff.
    Can be disabled with the --full-diff flag.
    """
    # Ignore custom hook if user wants full diff.
    if config.getoption("--full-diff", default=False):
        return

    # Force creation of full diff report when reporting on parse results.
    type_report = '"type": "report"'
    if (
            op == "=="
            and isinstance(left, str)
            and isinstance(right, str)
            and type_report in left
            and type_report in right
    ):
        diff = difflib.unified_diff(right.splitlines(True), left.splitlines(True), "Expected", "Actual")
        return ["", *(line.rstrip("\n") for line in diff)]


@pytest.fixture
def test_file(tmpdir):
    """Fixture for providing a test file to pass to mwcp."""
    file_path = tmpdir / 'test.txt'
    file_path = file_path.write_binary(b'This is some test data!')
    return file_path


@pytest.fixture
def test_dir(tmpdir):
    """Fixture for providing a test directory to pass to mwcp."""
    directory = tmpdir.mkdir('test_dir')
    for i in range(5):
        file_path = directory / 'test_{}.txt'.format(i)
        file_path.write_binary(b"This is some test data!")
    return directory


# language=Python
TEST_PARSER = u'''
from mwcp import Parser

class Downloader(Parser):
    DESCRIPTION = "TestParser Downloader"

        
class Implant(Parser):
    DESCRIPTION = "TestParser Implant"
    
'''

# language=Yaml
TEST_PARSER_CONFIG = u'''
Sample:
    description: A test parser
    author: Mr. Tester
    parsers:
        - .Downloader
        - .Implant
'''


@pytest.fixture
def make_sample_parser(tmpdir):
    """
    Creates and returns a function to generate a sample parser with the
    given name as the directory (this allows us to make multiple directories if desired.)
    """

    def _make_sample_parser(
            source_name="acme",
            parser_name="Sample",
            parser_code=TEST_PARSER,
            config_text=TEST_PARSER_CONFIG
    ):
        directory = tmpdir / source_name
        directory.mkdir()

        parser_file = directory / f"{parser_name}.py"
        parser_file.write_text(parser_code, 'utf8')

        # Parser directories must have an __init__.py
        init = directory / '__init__.py'
        init.write_text(u'', 'utf8')

        config_file = directory / 'parser_config.yml'
        config_file.write_text(config_text, 'utf8')

        return parser_file, config_file

    return _make_sample_parser


@pytest.fixture
def report():
    """
    Creates an empty report for testing.
    """
    import logging
    logger = logging.getLogger("test_report")
    logging.root.setLevel(logging.DEBUG)
    input_file = mwcp.FileObject(b"some data", file_path="C:/input_file.bin")
    return mwcp.Report(input_file, "FooParser")


@pytest.fixture
def metadata_items() -> List[Metadata]:
    """
    Collection of example metadata elements for each type.
    This is used in number of different basic tests.
    """
    return [
        metadata.Path2("C:\\windows\\temp\\1\\log\\keydb.txt", is_dir=False),
        metadata.Directory("%APPDATA%\\foo"),
        metadata.FilePath("C:\\foo\\bar.txt"),
        metadata.FileName("malware.exe"),
        metadata.Base16Alphabet("0123456789ABCDEF"),
        metadata.Base32Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="),
        metadata.Base64Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
        metadata.Command("cmd.exe /c notepad.exe"),
        metadata.Credential(username="admin", password="123456"),
        metadata.Username("mruser"),
        metadata.Password("secrets"),
        metadata.CryptoAddress("14qViLJfdGaP4EeHnDyJbEGQysnCpwk3gd", "BTC"),
        metadata.ScheduledTask("calc.exe", name="CalcTask"),
        metadata.ScheduledTask([
            metadata.Command("notepad.exe", cwd=r"C:\Windows\Temp"),
            'cmd.exe /c "echo hi"',
        ],
            name="Complex Task", description="Some task with multiple commands",
            credentials=metadata.Credential("admin", "pass"),
        ),
        metadata.Socket(address="bad.com", port=21, network_protocol="tcp"),
        metadata.C2SocketAddress(address="website.com", port=123),
        metadata.Port(1635, protocol="udp"),
        metadata.ListenPort(4568, protocol="tcp"),
        metadata.Network(
            url=metadata.URL2(url="https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
            socket=metadata.Socket(port=8080),
            credential=metadata.Credential(username="You", password="Tube")
        ),
        metadata.Network(
            url=metadata.URL2(url="https://www.github.com"),
            credential=metadata.Credential(username="Malware", password="ConfigurationParser")
        ),
        metadata.Network(
            url=metadata.URL2(url="https://www.gitlab.com"),
            socket=metadata.Socket(address="1.2.3.4", port=8080, network_protocol="udp")
        ),
        metadata.URL2(url="url.url.url"),
        metadata.URL("https://10.11.10.13:443/images/baner.jpg"),
        metadata.C2URL(url="http://[fe80::20c:1234:5678:9abc]:80/badness"),
        metadata.URLPath("url/path.jpg"),
        metadata.URLQuery("query?answer=42"),
        metadata.Proxy(
            username="admin",
            password="pass",
            address="192.168.1.1",
            port=80,
            protocol="tcp",
        ),
        metadata.ProxySocketAddress(
            address="12.34.56.78",
            port=90,
            protocol="tcp"
        ),
        metadata.ProxyAddress(
            address="255.255.255.255"
        ),
        metadata.FTP(
            username="admin",
            password="pass",
            url="ftp://badhost.com:21",
        ),
        metadata.FTP(
            username="password",
            password="username",
            address="123.45.67.89",
            port=0
        ),
        metadata.EmailAddress("email@bad.com"),
        metadata.Event("MicrosoftExist"),
        metadata.UUID("654e5cff-817c-4e3d-8b01-47a6f45ae09a"),
        metadata.InjectionProcess("svchost"),
        metadata.Interval(3),
        metadata.EncryptionKey(b"hello", algorithm="rc4"),
        metadata.EncryptionKey(b"\xff\xff\xff\xff", algorithm="aes", mode="ecb", iv=b"\x00\x00\x00\x00"),
        metadata.DecodedString("GetProcess"),
        # Github issue #31
        metadata.DecodedString(
            "badstring",
            encryption_key=metadata.EncryptionKey(b"\xff\xff", algorithm="xor")),
        metadata.MissionID("target4"),
        metadata.Mutex("ithinkimalonenow"),
        metadata.Other("misc_info", "some miscellaneous info").add_tag("something"),
        metadata.Other("random_data", b"\xde\xad\xbe\xef"),
        metadata.Other("keylogger", True),
        metadata.Other("misc_integer", 432).add_tag("tag1"),
        metadata.Pipe("\\.\\pipe\\namedpipe"),
        metadata.Registry2(
            subkey="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            value="Updater",
            data="c:\\update.exe",
        ),
        metadata.Registry2(subkey="HKLM\\Foo\\Bar"),
        metadata.Registry2(value="Baz").add_tag("tag2"),
        metadata.RSAPrivateKey(
            public_exponent=0x07,
            modulus=0xbb,
            private_exponent=0x17,
            p=0x11,
            q=0x0b,
            d_mod_p1=0x07,
            d_mod_q1=0x03,
            q_inv_mod_p=0x0e,
        ),
        metadata.RSAPublicKey(
            public_exponent=0x07,
            modulus=0xbb,
        ),
        metadata.Service(
            name="WindowsUserManagement",
            display_name="Windows User Management",
            description="Provides a common management to access information about windows user.",
            image="%System%\\svohost.exe",
        ),
        metadata.UserAgent("Mozilla/4.0 (compatible; MISE 6.0; Windows NT 5.2)"),
        metadata.Version("3.1"),
        metadata.Version("403.10"),
        metadata.File(
            name="config.xml",
            description="Extracted backdoor Foo config file",
            data=b"foo = bar",
            derivation="embedded"
        ),
    ]
