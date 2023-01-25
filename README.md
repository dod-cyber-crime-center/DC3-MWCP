# DC3-MWCP
[Changelog](CHANGELOG.md) | [Releases](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/releases)

DC3 Malware Configuration Parser (DC3-MWCP) is a framework for parsing configuration information from malware.
The information extracted from malware includes items such as addresses, passwords, filenames, and
mutex names. A parser module is usually created per malware family.
DC3-MWCP is designed to help ensure consistency in parser function and output, ease parser development,
and facilitate parser sharing. DC3-MWCP supports both analyst directed analysis and
large-scale automated execution, utilizing either the native python API, a REST API, or a provided
command line tool. DC3-MWCP is authored by the Defense Cyber Crime Center (DC3).

- [Install](#install)
- [Builtin Parsers](#builtin-parsers)
- [Dragodis Support](#dragodis-support)
- [DC3-Kordesii Support](#dc3-kordesii-support)
- [Usage](#usage)
    - [CLI Tool](#cli-tool)
    - [REST API](#rest-api)
    - [Python API](#python-api)
- [Schema](#schema)
- [STIX Output](#stix-output)
- [YARA Matching](#yara-matching)
- [Helper Utilities](#helper-utilities)

### Guides
- [Parser Development](docs/ParserDevelopment.md)
- [Parser Components](docs/ParserComponents.md)
- [Parser Installation](docs/ParserInstallation.md)
- [Parser Testing](docs/ParserTesting.md)
- [Python Style Guide](docs/PythonStyleGuide.md)
- [Construct Tutorial](docs/construct.ipynb)
- [Style Guide](docs/PythonStyleGuide.md)
- [Testing](docs/Testing.md)


## Install
```console
> pip install mwcp
```

Alternatively you can clone this repo and install locally.
```console
> git clone https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP.git
> pip install ./DC3-MWCP
```

For a development mode use the `-e` flag to install in editable mode:

```console
> git clone https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP.git
> pip install -e ./DC3-MWCP
```

## Builtin Parsers
DC3-MWCP includes a handful of builtin [parsers](./mwcp/parsers) to get you started.
These can be used as-is, subclassed, or included in your own parser groups.

To view the available parsers:
```bash
$ mwcp list
```

Parsers are installed under the `dc3` source name. To include them in a group simply add them with
the `dc3:` prefix.

```yml
SuperMalware:
    description: SuperMalware component
    author: acme
    parsers:
      - dc3:Archive.Zip
      - .Dropper
      - .Implant
      - dc3:Decoy
```


## Dragodis Support
DC3-MWCP optionally supports [Dragodis](https://github.com/Defense-Cyber-Crime-Center/Dragodis)
if it is installed. This allows you to obtain a disassembler agnostic interface for parsing
the file's disassembly from the `mwcp.FileObject` object with the `.disassembly()` function.

You can install Dragodis along with DC3-MWCP by adding `[dragodis]` to your appropriate install command:
```
pip install mwcp[dragodis]
pip install ./DC3-MWCP[dragodis]
pip install -e ./DC3-MWCP[dragodis]
```

After installation make sure to follow Dragodis's [installation instructions](https://github.com/Defense-Cyber-Crime-Center/Dragodis/blob/master/docs/install.rst) to setup
a backend disassembler.

*It is recommended to also install [Rugosa](https://github.com/Defense-Cyber-Crime-Center/rugosa) 
for emulation and regex/yara matching capabilities using Dragodis.*


## DC3-Kordesii Support
DC3-MWCP optionally supports [DC3-Kordesii](https://github.com/Defense-Cyber-Crime-Center/kordesii)
if it is installed. This will allow you to run any DC3-Kordesii decoder from the
`mwcp.FileObject` object with the `run_kordesii_decoder` function.

You can install DC3-Kordesii along with DC3-MWCP by adding `[kordesii]` to your appropriate install command:
```
pip install mwcp[kordesii]
pip install ./DC3-MWCP[kordesii]
pip install -e ./DC3-MWCP[kordesii]
```


## Usage
DC3-MWCP is designed to allow easy development and use of malware config parsers. DC3-MWCP is also designed to ensure
that these parsers are scalable and that DC3-MWCP can be integrated in other systems.

Most automated processing systems will use a condition, such as a yara signature match, to trigger execution
of an DC3-MWCP parser.

There are 3 options for integration of DC3-MWCP:
- CLI: `mwcp`
- REST API: `mwcp serve`
- Python API

DC3-MWCP also includes a utility for test case generation and execution.

### CLI tool

DC3-MWCP can be used directly from the command line using the `mwcp` command.

```console
> mwcp parse foo ./README.md
----- File: README.md -----
Field         Value
------------  ----------------------------------------------------------------
Parser        foo
File Path     README.md
Description   Foo
Architecture
MD5           b21df2332fe87c0fae95bdda00b5a3c0
SHA1          8841a1fff55687ccddc587935b62667173b14bcd
SHA256        0097c13a3541a440d64155a7f4443d76597409e0f40ce3ae67f73f51f59f1930
Compile Time
Tags

---- Socket ----
Tags    Address    Network Protocol
------  ---------  ------------------
        127.0.0.1  tcp

---- URL ----
Tags    Url               Address    Network Protocol    Application Protocol
------  ----------------  ---------  ------------------  ----------------------
        http://127.0.0.1  127.0.0.1  tcp                 http

---- Residual Files ----
Tags    Filename           Description          MD5                               Arch    Compile Time
------  -----------------  -------------------  --------------------------------  ------  --------------
        fooconfigtest.txt  example output file  5eb63bbbe01eeed093cb22bb8f5acdc3

---- Logs ----
[+] File README.md identified as Foo.
[+] size of inputfile is 15560 bytes
[+] README.md dispatched residual file: fooconfigtest.txt
[+] File fooconfigtest.txt described as example output file
[+] operating on inputfile README.md

----- File Tree -----
<README.md (b21df2332fe87c0fae95bdda00b5a3c0) : Foo>
└── <fooconfigtest.txt (5eb63bbbe01eeed093cb22bb8f5acdc3) : example output file>
```

see ```mwcp parse -h``` for full set of options


### REST API

DC3-MWCP can be used as a web service. The web service provides a web application as
well as a REST API for some commonly used functions:

* ```/run_parser/<parser>``` -- executes a parser on uploaded file
* ```/descriptions``` -- provides list of available parsers
* ```/schema.json``` -- provides the [schema](#schema) for report output

To use, first start the server by running:
```console
> mwcp serve
```

Then you can either use an HTTP client to create REST requests.

Using cURL:
```console
# Get JSON for processing README.md with foo parser
> curl --form data=@README.md http://localhost:8080/run_parser/foo
# Get STIX 2.1 JSON for processing README.md with foo parser
> curl --form data=@README.md --form output=stix http://localhost:8080/run_parser/foo
# Get STIX 2.1 JSON  without artifacts for processing README.md with foo parser
> curl --form data=@README.md --form output=stix --form no_file_data=1 http://localhost:8080/run_parser/foo
```

Using Python requests:
```python
import requests
req = requests.post("http://localhost:8080/run_parser/foo", files={'data': open("README.md", 'rb')})
req.json()
```

Output:
```json
{
    "url": [
        "http://127.0.0.1"
    ],
    "address": [
        "127.0.0.1"
    ],
    "debug": [
        "size of inputfile is 7128 bytes",
        "outputfile: fooconfigtest.txt",
        "operating on inputfile C:\\Users\\JOHN.DOE\\AppData\\Local\\Temp\\mwcp-managed_tempdir-pk0f12oh\\mwcp-inputfile-n4mw7uw3"
    ],
    "outputfile": [
        [
            "fooconfigtest.txt",
            "example output file",
            "5eb63bbbe01eeed093cb22bb8f5acdc3",
            "aGVsbG8gd29ybGQ="
        ]
    ],
    "output_text": "\n----Standard Metadata----\n\nurl                  http://127.0.0.1\naddress              127.0.0.1\n\n----Debug----\n\nsize of inputfile is 7128 bytes\noutputfile: fooconfigtest.txt\noperating on inputfile C:\\Users\\JOHN.DOE\\AppData\\Local\\Temp\\mwcp-managed_tempdir-pk0f12oh\\mwcp-inputfile-n4mw7uw3\n\n----Output Files----\n\nfooconfigtest.txt    example output file\n                     5eb63bbbe01eeed093cb22bb8f5acdc3\n"
}
```

By default, the original legacy json schema will be provided upon request.
To use the new schema, you must set the `legacy` option in the query section to `False`.

Eventually this new schema will replace the old one entirely. It is recommended to start using this flag
to help transition your automation platform to use the new schema.


```console
> curl --form data=@README.md http://localhost:8080/run_parser/foo?legacy=False
```

```json
[
    {
        "type": "report",
        "tags": [],
        "input_file": {
            "type": "input_file",
            "tags": [],
            "name": "README.md",
            "description": "Foo",
            "md5": "80a3d9b88c956c960d1fea265db0882e",
            "sha1": "994aa37fd26dd88272b8e661631eec8a5f425920",
            "sha256": "3bef8d5dc4cd94c0ee92c9b6d7ee47a4794e550d287ee1affde84c2b7bcdf3cb",
            "architecture": null,
            "compile_time": null,
            "file_path": "README.md",
            "data": null
        },
        "parser": "foo",
        "errors": [],
        "logs": [
            "[+] File README.md identified as Foo.",
            "[+] size of inputfile is 15887 bytes",
            "[+] README.md dispatched residual file: fooconfigtest.txt",
            "[+] File fooconfigtest.txt described as example output file",
            "[+] operating on inputfile README.md"
        ],
        "metadata": [
            {
                "type": "url",
                "tags": [],
                "url": "http://127.0.0.1",
                "socket": {
                    "type": "socket",
                    "tags": [],
                    "address": "127.0.0.1",
                    "port": null,
                    "network_protocol": "tcp",
                    "c2": null,
                    "listen": null
                },
                "path": null,
                "query": "",
                "application_protocol": "http",
                "credential": null
            },
            {
                "type": "socket",
                "tags": [],
                "address": "127.0.0.1",
                "port": null,
                "network_protocol": "tcp",
                "c2": null,
                "listen": null
            },
            {
                "type": "residual_file",
                "tags": [],
                "name": "fooconfigtest.txt",
                "description": "example output file",
                "md5": "5eb63bbbe01eeed093cb22bb8f5acdc3",
                "sha1": "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
                "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                "architecture": null,
                "compile_time": null,
                "file_path": "README.md_mwcp_output\\5eb63_fooconfigtest.txt",
                "data": null
            }
        ]
    }
]
```

A simple HTML interface is also available at the same address. By default this
is `http://localhost:8080/`. Individual samples can be submitted and results
saved as JSON, plain text, or ZIP archives.


### Python API
DC3-MWCP can be run directly from Python.

```python
#!/usr/bin/env python
"""
Simple example to demonstrate use of the API provided by DC3-MWCP framework.
"""

# first, import mwcp
import mwcp

# register the builtin MWCP parsers and any other parser packages installed on the system
mwcp.register_entry_points()

# register a directory containing parsers
mwcp.register_parser_directory(r'C:\my_parsers')

# view all available parsers
print(mwcp.get_parser_descriptions(config_only=False))

# call the run() function to to generate a mwcp.Report object.
report = mwcp.run("FooParser", "C:\\README.md")
# alternate, run on provided buffer:
report = mwcp.run("FooParser", data=b"lorem ipsum")

# Display report results in a variety of formats:
print(report.as_dict())
print(report.as_json())
print(report.as_text())

# The metadata schema has changed recently. To get the legacy format use the following:
print(report.as_dict_legacy())
print(report.as_json_legacy())

# You can also programmatically view results of report:
from mwcp import metadata

# display errors that may occur
for log in report.errors:
  print(log)

# display data about original input file
print(report.input_file)

# get all url's using ftp protocol or has a query
for url in report.get(metadata.URL):
  if url.application_protocol == "ftp" or url.query:
    print(url.url)

# get residual files
for residual_file in report.get(metadata.File):
  print(residual_file.name)
  print(residual_file.description)
  print(residual_file.md5)

# iterate through all metadata elements
for element in report:
  print(element)

```

## Configuration
DC3-MWCP uses a configuration file which is located within the user's 
profile directory. (`%APPDATA%\Local\mwcp\config.yml` for Windows or `~/.config/mwcp/config.yml` for Linux)

This configuration file is used to manage configurable parameters, such as the location
of the malware repository used for testing or the default parser source.

To configure this file, run `mwcp config` to open up the file in your default text
editor.

An alternative configuration file can also be temporarily set using the `--config` parameter.
```console
> mwcp --config='new_config.yml' test Foo
```

Individual configuration parameters can be overwritten on the command line using the respective parameter.


## Logging
DC3-MWCP uses Python's builtin in `logging` module to log all messages.
By default, logging is configured using the [log_config.yml](mwcp/config/log_config.yml) configuration
file. Which is currently set to log all messages to the console and error messages to `%LOCALAPPDATA%/mwcp/errors.log`. 

You can provide your own custom log configuration file by adding the path
to the configuration parameter `LOG_CONFIG_PATH`. 
(Please see [Python's documentation](http://docs.python.org/dev/library/logging.config.html) for more information on how to write your own configuration file.)

You may also use the `--verbose` or `--debug` flags to adjust the logging level when using the `mwcp` tool.


## Schema

One of the major goals of DC3-MWCP is to standardize output for malware configuration parsers, making the data
from one parser comparable with that of other parsers. This is achieved by establishing a schema of
standardized metadata elements that represent the common malware configuration items seen across malware families.

A formal [JSON Schema](https://json-schema.org) can be found at [schema.json](/mwcp/config/schema.json), by calling `mwcp schema` in the command line, or programmatically by calling `mwcp.schema()`. 
This schema is versioned the same as DC3-MWCP. A change in the version may not necessarily
reflect a change in the actual schema. However, any major or minor changes to the schema will
be reflected in an appropriate change to the version and will be noted in the [changelog](/CHANGELOG.md).
Please ensure you pin DC3-MWCP appropriately.

It is acknowledged that a set of generic elements will often not be adequate to capture the nuances of
individual malware families. To ensure that malware family specific attributes are appropriately captured
in parser output, the schema includes an "Other" element which supports arbitrary key-value pairs.
The keys and values are arbitrary to permit flexibility in describing the peculiarities of individual malware families.
Information
not captured in the abstract standardized elements is captured through this mechanism.

The use of [tags](/docs/ParserComponents.md#tagging) is encouraged to provide additional context for the configuration items.
For example, if a specific url is used to download a second stage component, a tag of "download"
could be added to the reported URL element. Alternatively, if the URL is used for a proxy, 
a tag of "proxy" could be included.
There is no standard on what tags are available or when they should be included.
This should be determined by your organization.


### Extending the Schema

It is possible to extend the schema to include your own custom metadata elements.
This can be accomplished by creating a class that inherits from `mwcp.metadata.Metadata`. 
This class must be decorated with [attr](https://attrs.org) using the custom configuration `mwcp.metadata.config`. 

*NOTE: The class name must be unique from other metadata elements.*

```python
from typing import List

import attr

import mwcp
from mwcp import metadata


@attr.s(**metadata.config)
class MyCustom(metadata.Metadata):
    """
    This is my custom metadata item.
    """
    field_a: str
    field_b: int
    field_c: List[str] = attr.ib(factory=list)

    
item = MyCustom(field_a="hello", field_b=42, field_c=["a", "b"])

print(item)
print(item.as_dict())

# Custom items can be included in the report like normal.
# MWCP will automatically format and display the custom element in the report.
report = mwcp.Report()
with report:
    report.add(item)

print(report.as_text())
```

```
MyCustom(tags=set(), field_a='hello', field_b=42, field_c=['a', 'b'])
{'type': 'my_custom', 'tags': [], 'field_a': 'hello', 'field_b': 42, 'field_c': ['a', 'b']}
---- My Custom ----
Tags    Field A      Field B  Field C
------  ---------  ---------  ----------
        hello             42  a, b
```


Please note, that extending the schema will obviously cause the [schema.json](/mwcp/config/schema.json) file to be incorrect.
To regenerate the schema to also include the custom element run `mwcp.schema()` afterwards.

```python
import json
import mwcp

with open("schema.json", "w") as fo:
    json.dump(mwcp.schema(id="https://acme.org/0.1/schema.json"), fo, indent=4)
```


## STIX Output

MWCP can generate a [STIX 2.1](https://www.oasis-open.org/standard/stix-version-2-1/) JSON output that is suitable for integration into many
systems that support the STIX standard. This output format makes use of three SCO 
extensions and one property extension in addition to the currently defined STIX
objects order to accurately convey MWCP's scan results.

Some tools may not support these extensions yet which can result in the following data
being omitted when ingesting MWCP's STIX output.  The following provides a list of STIX
objects and extensions are used and what MWCP classes these are associated with:

1. artifact (SCO)
    1. File -- only used if the original binary is requested
2. crypto-currency-address (SCO Extension)
    1. CryptoAddress
3. directory (SCO)
    1. File
    2. Path
    3. Service
4. domain-name (SCO)
    1. Socket
    2. URL
5. email-address (SCO)
    1. EmailAddress
6. file (SCO)
    1. File
    2. Path
    3. Service
7. ipv4-address (SCO)
    1. Socket
    2. URL
8. ipv6-address (SCO)
    1. Socket
    2. URL
9. malware-analysis (SDO)
    1. MWCP's scan results are tied together via a malware-analysis object showing the input object and the outputs
10. mutex (SCO)
    1. Mutex
11. network-traffic (SCO)
    1. Socket
    2. URL
12. note (SDO)
    1. Boolean and Integer values for Other.  These are added to the description of the Note.
    2. Descriptions and other narrative text tied to SCOs
    3. Tags for SCOs excluding files
13. observed-string (SCO Extension)
    1. DecodedString
    2. MissionID
    3. Other
    4. Pipe
    5. User Agent
    6. UUID
14. process (SCO)
    1. Command
    2. Service
15. relationship (SRO)
    1. DecodedString
    2. URL
16. RSA Private Key (Property Extension for x509-certificate)
    1. RSAPrivateKey
17. symmetric-encryption (SCO)
    1. EncryptionKey
18. user-account (SCO)
    1. Credential
19. url (SCO)
    1. URL
20. x509-certificate (SCO)
    1. RSAPrivateKey
    2. RSAPublicKey
    3. SSLCertSHA1
21. windows-registry-key (SCO)
    1. Registry2


## YARA Matching

MWCP includes a runner that can use YARA match results to determine which parser(s) to run on a given file.

This will be used whenever you use `-` instead of specifying a parser on the command line,
when a parser isn't specified in `mwcp.run()`, or when a parser isn't specified in a server request.

```bash
$ mwcp parse - input.exe
$ curl --form data=@input.exe http://localhost:8080/run_parser
```

```python
import mwcp 
mwcp.register_entry_points()

report = mwcp.run(data=b"file data")
```

As well, YARA matching will be recursively used on unidentified residual files.
If you want to disable this, either set `--no-recursive` on the command line or set `recursive=False` on `mwcp.run()`.

### Setup

To enable YARA matching you'll need to specify a directory containing YARA signatures which use the `mwcp` 
meta field to map a signature to a comma delimited list of parsers. Parsers can be specified in the same
way as on the command line or Python API. That is, parser group names, `.` notation for specific parser components,
and the use of `:` for specifying a parser source are all valid.

Any signatures that don't have the `mwcp` meta field will be ignored.

```yara
rule SuperMalware {
    meta:
        mwcp = "SuperMalware"
    ...
}
```

To setup a YARA repo, set the `YARA_REPO` field to point to a directory containing YARA signatures (subdirectories allowed)
in the configuration file that appears when you call `mwcp config`.
If you have upgraded from an older version of MWCP, you may need to first backup and remove the original configuration file and
then run `mwcp config` again to have MWCP recreate the file.

Alternatively, the yara repo can be specified in the command line with `--yara-repo`. But the former method
is necessary to use YARA matching with the server.


### Testing

Recursive YARA matching for unidentified files can be done when creating test cases. Simply include the `--recursive` flag
when adding a new or updating an existing test case.

```bash
$ mwcp test SuperMalware --add="C:\input.exe" --recursive
$ mwcp test SuperMalware -u --recursive
```

Once a test case is created with recursion turned on, anybody running your test case must also have a YARA repo setup
with the same YARA signatures so the test will pass for them.
For this reason, it is recommended to turn on recursion for a test **only** if the parser's full functionality depends on it.


## Helper Utilities
MWCP comes with a few helper utilities (located in `mwcp.utils`) that may become useful for parsing malware files.

- `pefileutils` - Provides helper functions for common routines done with the `pefile` library. (obtaining or checking for exports, imports, resources, sections, etc.)
- `elffileutils` - Provides helper functions for common routines done with the `elftools` library. Provides a consistent interface similar to `pefileutils`.
- `custombase64` - Provides functions for base64 encoding/decoding data with a custom alphabet.
- `construct` - Provides extended functionality to the [construct](https://construct.readthedocs.io) library and brings
back some lost features from version 2.8 into 2.9.
    - This library has replaced the `enstructured` library originally found in the resources directory.
    - Please follow [this tutorial](docs/construct.ipynb) for migrating from `enstructured` to `construct`.
- `pecon` - PE file reconstruction utility.
    - Please see docstring in [pecon.py](mwcp/utils/pecon.py) for more information.
- `poshdeob` - An experimental powershell deobfuscator utility used to statically deobfuscate code and extract strings.
 