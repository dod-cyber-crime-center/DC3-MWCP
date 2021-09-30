"""
Tests Report class.
"""

import pytest

import mwcp
from mwcp import metadata
from mwcp.metadata import *


def test_report(report):
    with report:
        report.add(metadata.Path("C:\\windows\\temp\\1\\log\\keydb.txt", is_dir=False))
        report.add(metadata.Directory("%APPDATA%\\foo"))
        report.add(metadata.Base16Alphabet("0123456789ABCDEF"))
        report.add(metadata.Base32Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="))
        report.add(metadata.Base64Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="))
        report.add(metadata.Credential(username="admin", password="123456"))
        report.add(metadata.Socket(address="bad.com", port=21, network_protocol="tcp"))
        report.add(metadata.URL("https://10.11.10.13:443/images/baner.jpg"))
        report.add(metadata.Proxy(
            username="admin",
            password="pass",
            address="192.168.1.1",
            port=80,
            protocol="tcp",
        ))
        report.add(metadata.FTP(
            username="admin",
            password="pass",
            url="ftp://badhost.com:21",
        ))
        report.add(metadata.EmailAddress("email@bad.com"))
        report.add(metadata.Event("MicrosoftExist"))
        report.add(metadata.UUID("654e5cff-817c-4e3d-8b01-47a6f45ae09a"))
        report.add(metadata.InjectionProcess("svchost"))
        report.add(metadata.Interval(3))
        report.add(metadata.EncryptionKey(b"myrc4key", algorithm="rc4"))
        report.add(metadata.MissionID("target4"))
        report.add(metadata.Mutex("ithinkimalonenow"))
        report.add(metadata.Other(key="keylogger", value="True"))
        report.add(metadata.Pipe("\\.\\pipe\\namedpipe"))
        report.add(metadata.Registry(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            data="c:\\update.exe",
        ))
        report.add(metadata.RSAPrivateKey(
            public_exponent=0x07,
            modulus=0xbb,
            private_exponent=0x17,
            p=0x11,
            q=0x0b,
            d_mod_p1=0x07,
            d_mod_q1=0x03,
            q_inv_mod_p=0x0e,
        ))
        report.add(metadata.RSAPublicKey(
            public_exponent=0x07,
            modulus=0xbb,
        ))
        report.add(metadata.Service(
            name="WindowsUserManagement",
            display_name="Windows User Management",
            description="Provides a common management to access information about windows user.",
            image="%System%\\svohost.exe",
        ))
        report.add(metadata.UserAgent("Mozilla/4.0 (compatible; MISE 6.0; Windows NT 5.2)"))
        report.add(metadata.Version("3.1"))
        report.add(metadata.ResidualFile(
            name="config.xml",
            description="Extracted backdoor Foo config file",
            data=b"foo = bar"
        ))

        logger.info("Test info log")
        logger.error("Test error log")
        logger.debug("Test debug log")

    assert report.as_dict() == {
         "errors": [
             "[!] Test error log",
         ],
         "mwcp_version": mwcp.__version__,
         "input_file": {"architecture": None,
                        "compile_time": None,
                        "description": None,
                        "name": "input_file.bin",
                        "file_path": "C:/input_file.bin",
                        "md5": "1e50210a0202497fb79bc38b6ade6c34",
                        "sha1": "baf34551fecb48acc3da868eb85e1b6dac9de356",
                        "sha256": "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee",
                        "data": None,
                        "tags": [],
                        "type": "file"},
         "parser": "FooParser",
         "logs": [
             "[+] Test info log",
             "[!] Test error log",
             "[*] Test debug log",
         ],
         "metadata": [{"directory_path": "C:\\windows\\temp\\1\\log",
                       "file_system": None,
                       "is_dir": False,
                       "name": "keydb.txt",
                       "path": "C:\\windows\\temp\\1\\log\\keydb.txt",
                       "tags": [],
                       "type": "path"},
                      {"directory_path": "%APPDATA%",
                       "file_system": None,
                       "is_dir": True,
                       "name": "foo",
                       "path": "%APPDATA%\\foo",
                       "tags": [],
                       "type": "path"},
                      {"alphabet": "0123456789ABCDEF",
                       "base": 16,
                       "tags": [],
                       "type": "alphabet"},
                      {"alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=",
                       "base": 32,
                       "tags": [],
                       "type": "alphabet"},
                      {"alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
                       "base": 64,
                       "tags": [],
                       "type": "alphabet"},
                      {"password": "123456",
                       "tags": [],
                       "type": "credential",
                       "username": "admin"},
                      {"address": "bad.com",
                       "c2": None,
                       "listen": None,
                       "network_protocol": "tcp",
                       "port": 21,
                       "tags": [],
                       "type": "socket"},
                      {"application_protocol": "https",
                       "credential": None,
                       "path": "/images/baner.jpg",
                       "query": "",
                       "socket": {"address": "10.11.10.13",
                                  "c2": None,
                                  "listen": None,
                                  "network_protocol": None,
                                  "port": 443,
                                  "tags": [],
                                  "type": "socket"},
                       "tags": [],
                       "type": "url",
                       "url": "https://10.11.10.13:443/images/baner.jpg"},
                      {"address": "10.11.10.13",
                       "c2": None,
                       "listen": None,
                       "network_protocol": None,
                       "port": 443,
                       "tags": [],
                       "type": "socket"},
                      {"application_protocol": None,
                       "credential": {"password": "pass",
                                      "tags": [],
                                      "type": "credential",
                                      "username": "admin"},
                       "path": None,
                       "query": None,
                       "socket": {"address": "192.168.1.1",
                                  "c2": None,
                                  "listen": None,
                                  "network_protocol": "tcp",
                                  "port": 80,
                                  "tags": [],
                                  "type": "socket"},
                       "tags": ["proxy"],
                       "type": "url",
                       "url": None},
                      {"address": "192.168.1.1",
                       "c2": None,
                       "listen": None,
                       "network_protocol": "tcp",
                       "port": 80,
                       "tags": [],
                       "type": "socket"},
                      {"password": "pass",
                       "tags": [],
                       "type": "credential",
                       "username": "admin"},
                      {"application_protocol": "ftp",
                       "credential": {"password": "pass",
                                      "tags": [],
                                      "type": "credential",
                                      "username": "admin"},
                       "path": None,
                       "query": "",
                       "socket": {"address": "badhost.com",
                                  "c2": None,
                                  "listen": None,
                                  "network_protocol": None,
                                  "port": 21,
                                  "tags": [],
                                  "type": "socket"},
                       "tags": [],
                       "type": "url",
                       "url": "ftp://badhost.com:21"},
                      {"address": "badhost.com",
                       "c2": None,
                       "listen": None,
                       "network_protocol": None,
                       "port": 21,
                       "tags": [],
                       "type": "socket"},
                      {"tags": [],
                       "type": "email_address",
                       "value": "email@bad.com"},
                      {"tags": [], "type": "event", "value": "MicrosoftExist"},
                      {"tags": [],
                       "type": "uuid",
                       "value": uuid.UUID("654e5cff-817c-4e3d-8b01-47a6f45ae09a")},
                      {"tags": [], "type": "injection_process", "value": "svchost"},
                      {"tags": [], "type": "interval", "value": 3.0},
                      {"algorithm": "rc4",
                       "iv": None,
                       "key": b"myrc4key",
                       "mode": None,
                       "tags": [],
                       "type": "encryption_key"},
                      {"tags": [], "type": "mission_id", "value": "target4"},
                      {"tags": [], "type": "mutex", "value": "ithinkimalonenow"},
                      {"key": "keylogger",
                       "tags": [],
                       "type": "other",
                       "value": "True"},
                      {"tags": [], "type": "pipe", "value": "\\.\\pipe\\namedpipe"},
                      {"data": "c:\\update.exe",
                       "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                       "tags": [],
                       "type": "registry",
                       "value": "Updater"},
                      {"d_mod_p1": 7,
                       "d_mod_q1": 3,
                       "modulus": 187,
                       "p": 17,
                       "private_exponent": 23,
                       "public_exponent": 7,
                       "q": 11,
                       "q_inv_mod_p": 14,
                       "tags": [],
                       "type": "rsa_private_key"},
                      {"modulus": 187,
                       "public_exponent": 7,
                       "tags": [],
                       "type": "rsa_public_key"},
                      {"description": "Provides a common management to access "
                                      "information about windows user.",
                       "display_name": "Windows User Management",
                       "dll": None,
                       "image": "%System%\\svohost.exe",
                       "name": "WindowsUserManagement",
                       "tags": [],
                       "type": "service"},
                      {"directory_path": "%System%",
                       "file_system": None,
                       "is_dir": False,
                       "name": "svohost.exe",
                       "path": "%System%\\svohost.exe",
                       "tags": [],
                       "type": "path"},
                      {"tags": [],
                       "type": "user_agent",
                       "value": "Mozilla/4.0 (compatible; MISE 6.0; Windows NT 5.2)"},
                      {"tags": [], "type": "version", "value": "3.1"},
                      {"data": None,
                        "description": "Extracted backdoor Foo config file",
                        "file_path": None,
                        "md5": "8c41f2802904e53469390845cfeb2b28",
                        "sha1": "ce6519a1dc71510ee15e66b3926fd164a373803a",
                        "sha256": "81addbf732d9d6c24b1d3ede7afceef6a1cff59af7b63d01504a0913a6c6701a",
                        "architecture": None,
                        "compile_time": None,
                        "name": "config.xml",
                        "tags": [],
                        "type": "file"}
         ],
         "tags": [],
         "type": "report"
    }

    # language=json
    expected_json = r"""{
    "type": "report",
    "tags": [],
    "mwcp_version": "MWCP_VERSION",
    "input_file": {
        "type": "file",
        "tags": [],
        "name": "input_file.bin",
        "description": null,
        "md5": "1e50210a0202497fb79bc38b6ade6c34",
        "sha1": "baf34551fecb48acc3da868eb85e1b6dac9de356",
        "sha256": "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee",
        "architecture": null,
        "compile_time": null,
        "file_path": "C:/input_file.bin",
        "data": null
    },
    "parser": "FooParser",
    "errors": [
        "[!] Test error log"
    ],
    "logs": [
        "[+] Test info log",
        "[!] Test error log",
        "[*] Test debug log"
    ],
    "metadata": [
        {
            "type": "path",
            "tags": [],
            "path": "C:\\windows\\temp\\1\\log\\keydb.txt",
            "directory_path": "C:\\windows\\temp\\1\\log",
            "name": "keydb.txt",
            "is_dir": false,
            "file_system": null
        },
        {
            "type": "path",
            "tags": [],
            "path": "%APPDATA%\\foo",
            "directory_path": "%APPDATA%",
            "name": "foo",
            "is_dir": true,
            "file_system": null
        },
        {
            "type": "alphabet",
            "tags": [],
            "alphabet": "0123456789ABCDEF",
            "base": 16
        },
        {
            "type": "alphabet",
            "tags": [],
            "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=",
            "base": 32
        },
        {
            "type": "alphabet",
            "tags": [],
            "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
            "base": 64
        },
        {
            "type": "credential",
            "tags": [],
            "username": "admin",
            "password": "123456"
        },
        {
            "type": "socket",
            "tags": [],
            "address": "bad.com",
            "port": 21,
            "network_protocol": "tcp",
            "c2": null,
            "listen": null
        },
        {
            "type": "url",
            "tags": [],
            "url": "https://10.11.10.13:443/images/baner.jpg",
            "socket": {
                "type": "socket",
                "tags": [],
                "address": "10.11.10.13",
                "port": 443,
                "network_protocol": null,
                "c2": null,
                "listen": null
            },
            "path": "/images/baner.jpg",
            "query": "",
            "application_protocol": "https",
            "credential": null
        },
        {
            "type": "socket",
            "tags": [],
            "address": "10.11.10.13",
            "port": 443,
            "network_protocol": null,
            "c2": null,
            "listen": null
        },
        {
            "type": "url",
            "tags": [
                "proxy"
            ],
            "url": null,
            "socket": {
                "type": "socket",
                "tags": [],
                "address": "192.168.1.1",
                "port": 80,
                "network_protocol": "tcp",
                "c2": null,
                "listen": null
            },
            "path": null,
            "query": null,
            "application_protocol": null,
            "credential": {
                "type": "credential",
                "tags": [],
                "username": "admin",
                "password": "pass"
            }
        },
        {
            "type": "socket",
            "tags": [],
            "address": "192.168.1.1",
            "port": 80,
            "network_protocol": "tcp",
            "c2": null,
            "listen": null
        },
        {
            "type": "credential",
            "tags": [],
            "username": "admin",
            "password": "pass"
        },
        {
            "type": "url",
            "tags": [],
            "url": "ftp://badhost.com:21",
            "socket": {
                "type": "socket",
                "tags": [],
                "address": "badhost.com",
                "port": 21,
                "network_protocol": null,
                "c2": null,
                "listen": null
            },
            "path": null,
            "query": "",
            "application_protocol": "ftp",
            "credential": {
                "type": "credential",
                "tags": [],
                "username": "admin",
                "password": "pass"
            }
        },
        {
            "type": "socket",
            "tags": [],
            "address": "badhost.com",
            "port": 21,
            "network_protocol": null,
            "c2": null,
            "listen": null
        },
        {
            "type": "email_address",
            "tags": [],
            "value": "email@bad.com"
        },
        {
            "type": "event",
            "tags": [],
            "value": "MicrosoftExist"
        },
        {
            "type": "uuid",
            "tags": [],
            "value": "654e5cff-817c-4e3d-8b01-47a6f45ae09a"
        },
        {
            "type": "injection_process",
            "tags": [],
            "value": "svchost"
        },
        {
            "type": "interval",
            "tags": [],
            "value": 3.0
        },
        {
            "type": "encryption_key",
            "tags": [],
            "key": "bXlyYzRrZXk=",
            "algorithm": "rc4",
            "mode": null,
            "iv": null
        },
        {
            "type": "mission_id",
            "tags": [],
            "value": "target4"
        },
        {
            "type": "mutex",
            "tags": [],
            "value": "ithinkimalonenow"
        },
        {
            "type": "other",
            "tags": [],
            "key": "keylogger",
            "value": "True"
        },
        {
            "type": "pipe",
            "tags": [],
            "value": "\\.\\pipe\\namedpipe"
        },
        {
            "type": "registry",
            "tags": [],
            "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value": "Updater",
            "data": "c:\\update.exe"
        },
        {
            "type": "rsa_private_key",
            "tags": [],
            "public_exponent": 7,
            "modulus": 187,
            "private_exponent": 23,
            "p": 17,
            "q": 11,
            "d_mod_p1": 7,
            "d_mod_q1": 3,
            "q_inv_mod_p": 14
        },
        {
            "type": "rsa_public_key",
            "tags": [],
            "public_exponent": 7,
            "modulus": 187
        },
        {
            "type": "service",
            "tags": [],
            "name": "WindowsUserManagement",
            "display_name": "Windows User Management",
            "description": "Provides a common management to access information about windows user.",
            "image": "%System%\\svohost.exe",
            "dll": null
        },
        {
            "type": "path",
            "tags": [],
            "path": "%System%\\svohost.exe",
            "directory_path": "%System%",
            "name": "svohost.exe",
            "is_dir": false,
            "file_system": null
        },
        {
            "type": "user_agent",
            "tags": [],
            "value": "Mozilla/4.0 (compatible; MISE 6.0; Windows NT 5.2)"
        },
        {
            "type": "version",
            "tags": [],
            "value": "3.1"
        },
        {
            "type": "file",
            "tags": [],
            "name": "config.xml",
            "description": "Extracted backdoor Foo config file",
            "md5": "8c41f2802904e53469390845cfeb2b28",
            "sha1": "ce6519a1dc71510ee15e66b3926fd164a373803a",
            "sha256": "81addbf732d9d6c24b1d3ede7afceef6a1cff59af7b63d01504a0913a6c6701a",
            "architecture": null,
            "compile_time": null,
            "file_path": null,
            "data": null
        }
    ]
}"""
    expected_json = expected_json.replace("MWCP_VERSION", mwcp.__version__)
    assert report.as_json() == expected_json


def test_split_report():
    """
    Tests split metadata per file.
    """
    logger = logging.getLogger("test_split_report")
    logging.root.setLevel(logging.INFO)
    input_file = mwcp.FileObject(b"some data", file_path="C:/input_file.bin")
    report = mwcp.Report(input_file, "FooParser", log_level=logging.INFO)
    with report:
        logger.info("Info log in input_file.bin")
        logger.error("Error log in input_file.bin")
        report.add(metadata.Mutex("root_mutex"))

        sub_file = mwcp.FileObject(b"some other data", file_name="sub_file.exe")
        report.add(metadata.ResidualFile.from_file_object(sub_file))
        report.set_file(sub_file)
        logger.info("Info log in sub_file.exe")
        logger.error("Error log in sub_file.exe")
        report.add(metadata.Mutex("sub_mutex"))

    assert len(report.get()) == 3

    root_metadata = report.get(source=input_file.md5)
    assert len(root_metadata) == 2
    assert metadata.Mutex("root_mutex") in root_metadata

    sub_metadata = report.get(source=sub_file.md5)
    assert len(sub_metadata) == 1
    assert metadata.Mutex("sub_mutex") in sub_metadata

    assert report.logs == [
        "[+] Info log in input_file.bin",
        "[!] Error log in input_file.bin",
        "[+] Info log in sub_file.exe",
        "[!] Error log in sub_file.exe",
    ]
    assert report.errors == [
        "[!] Error log in input_file.bin",
        "[!] Error log in sub_file.exe",
    ]
    assert report.get_logs(sub_file) == [
        "[+] Info log in sub_file.exe",
        "[!] Error log in sub_file.exe",
    ]
    assert report.get_logs(sub_file, errors_only=True) == [
        "[!] Error log in sub_file.exe",
    ]

    assert report.as_list() == [
        {
            "errors": [
                "[!] Error log in input_file.bin",
            ],
            "logs": [
                "[+] Info log in input_file.bin",
                "[!] Error log in input_file.bin",
            ],
            "mwcp_version": mwcp.__version__,
            "input_file": {
                "architecture": None,
                "compile_time": None,
                "data": None,
                "description": None,
                "file_path": "C:/input_file.bin",
                "md5": "1e50210a0202497fb79bc38b6ade6c34",
                "name": "input_file.bin",
                "sha1": "baf34551fecb48acc3da868eb85e1b6dac9de356",
                "sha256": "1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee",
                "tags": [],
                "type": "file"
            },
            "metadata": [
                {
                    "tags": [],
                    "type": "mutex",
                    "value": "root_mutex"
                },
                {
                    "architecture": None,
                    "compile_time": None,
                    "data": None,
                    "description": None,
                    "file_path": None,
                    "md5": "4844437d5747acd52a54981b48f60c8e",
                    "name": "sub_file.exe",
                    "sha1": "7bd8e7cb8e1e8b7b2e94b472422512935c9d4519",
                    "sha256": "c2b8761db47791e06799e99a698ed4d63cdbdb9f5f16224c90b625b02581350c",
                    "tags": [],
                    "type": "file"
                }
            ],
            "parser": None,
            "tags": [],
            "type": "report"
        },
        {
            "errors": [
                "[!] Error log in sub_file.exe",
            ],
            "logs": [
                "[+] Info log in sub_file.exe",
                "[!] Error log in sub_file.exe",
            ],
            "mwcp_version": mwcp.__version__,
            "input_file": {
                "architecture": None,
                "compile_time": None,
                "data": None,
                "description": None,
                "file_path": None,
                "md5": "4844437d5747acd52a54981b48f60c8e",
                "name": "sub_file.exe",
                "sha1": "7bd8e7cb8e1e8b7b2e94b472422512935c9d4519",
                "sha256": "c2b8761db47791e06799e99a698ed4d63cdbdb9f5f16224c90b625b02581350c",
                "tags": [],
                "type": "file"
            },
            "metadata": [
                {
                    "tags": [],
                    "type": "mutex",
                    "value": "sub_mutex"
                }
            ],
            "parser": None,
            "tags": [],
            "type": "report"
        }
    ]


def test_finalized(report):
    """
    Tests that we can't add metadata after it is finalized.
    """
    with report:
        report.add(metadata.URL("example1.com"))
    with pytest.raises(RuntimeError):
        report.add(metadata.URL("example2.com"))


def test_deduplication(report):
    """
    Tests that the same metadata information is dedupped.
    """
    with report:
        report.add(metadata.URL("example.com"))
        report.add(metadata.URL("example.com"))
        report.add(metadata.Socket(address="example.com"))
        report.add(metadata.Socket(address="example.com"))  # equivalent more verbose version.
        report.add(metadata.Socket(address="example.com", c2=True))

        # Set new file source to ensure we dedup across sources (if not split)
        res_file = mwcp.FileObject(b"residual data", file_name="res.exe")
        report.set_file(res_file)
        report.add(metadata.URL("example.com"))
        report.add(metadata.Socket(address="example.com"))

    items = report.get()
    assert items == [
        metadata.URL("example.com"),
        metadata.Socket(address="example.com"),
        metadata.Socket(address="example.com", c2=True),
    ]
