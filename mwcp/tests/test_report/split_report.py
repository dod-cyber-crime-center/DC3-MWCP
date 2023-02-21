
import mwcp


split_report = [
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
            "derivation": None,
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
                "derivation": None,
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
        "recursive": False,
        "external_knowledge": {},
        "tags": ["tagging", "test"],
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
            "derivation": None,
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
        "recursive": False,
        "external_knowledge": {},
        "tags": ["tagging", "test"],
        "type": "report"
    }
]
