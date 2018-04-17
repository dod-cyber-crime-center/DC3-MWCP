# DC3-MWCP
[Changelog](CHANGELOG.md) | [Releases](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/releases)

DC3 Malware Configuration Parser (DC3-MWCP) is a framework for parsing configuration information from malware.
The information extracted from malware includes items such as addresses, passwords, filenames, and
mutex names. A parser module is usually created per malware family.
DC3-MWCP is designed to help ensure consistency in parser function and output, ease parser development,
and facilitate parser sharing. DC3-MWCP supports both analyst directed analysis and
large-scale automated execution, utilizing either the native python API, a REST API, or a provided
command line tool. DC3-MWCP is authored by the Defense Cyber Crime Center (DC3).

## TOC
- [Install](#install)
- [Usage](#usage)
    - [CLI Tool](#cli-tool)
    - [REST API](#rest-api)
    - [Python API](#python-api)
- [Updates](#updates)
- [Schema](#schema)

### Documentation
- [Parser Installation](docs/ParserInstallation.md)
- [Parser Development](docs/ParserDevelopment.md)
- [Dispatch Parser Development](docs/DispatcherParserDevelopment.md)
- [Construct Tutorial](docs/construct.ipynb)

## Install

```
pip install mwcp
```

Alternatively you can clone this repo and install locally.
```bash
git clone https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP.git
pip install ./DC3-MWCP
```

For a development mode use the `-e` flag to install in editable mode:
```
git clone https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP.git
pip install -e ./DC3-MWCP
```

When installing locally from a cloned repo, you may need to
install the [kordesii](https://github.com/Defense-Cyber-Crime-Center/kordesii)
dependency first.

## No-install Method
You can also use MWCP without installing using the *mwcp-\*.py* scripts.
However, you will need to manually install all the dependencies.
You can find the dependencies listed in the `setup.py` file.

*This method is not recommended and is only here for backwards compatibility.*

Example:
```
python mwcp-tool.py -h
```

## Usage
DC3-MWCP is designed to allow easy development and use of malware config parsers. DC3-MWCP is also designed to ensure
that these parsers are scalable and that DC3-MWCP can be integrated in other systems.

Most automated processing systems will use a condition, such as a yara signature match, to trigger execution
of an DC3-MWCP parser.

There are 3 options for integration of DC3-MWCP:
- CLI: `mwcp-tool`
- REST API based on wsgi/bottle: `mwcp-server`, `mwcp-client`
- python API: `mwcp_api_example.py`

DC3-MWCP also includes a utility for test case generation and execution: `mwcp-test`

### CLI tool

DC3-MWCP can be used directly from the command line using the `mwcp-tool` command.

Input:
```sh
mwcp-tool -p foo README.md
```

Output:
```
----Standard Metadata----

url                  http://127.0.0.1
address              127.0.0.1

----Debug----

size of inputfile is 7963 bytes
outputfile: fooconfigtest.txt
operating on inputfile README.md

----Output Files----

fooconfigtest.txt    example output file
                     5eb63bbbe01eeed093cb22bb8f5acdc3
```

see ```mwcp-tool -h``` for full set of options


### REST API

DC3-MWCP can be used as a web service. The REST API provides two commonly used functions:

* ```/run_parser/<parser>``` -- executes a parser on uploaded file
* ```/descriptions``` -- provides list of available parsers

To use, first start the server by running:
```
mwcp-server
```

Then you can either use `mwcp-client` or create REST requests.

Input:
```sh
mwcp-client --host=localhost:8080 --parser=foo README.md
# OR
curl --form data=@README.md http://localhost:8080/run_parser/foo
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
    "output_text": "\n----Standard Metadata----\n\nurl                  http://127.0.0.1\naddress              127.0.0.1\n\n----Debug----\n\nsize of inputfile
is 7128 bytes\noutputfile: fooconfigtest.txt\noperating on inputfile C:\\Users\\JOHN.DOE\\AppData\\Local\\Temp\\mwcp-managed_tempdir-pk0f12oh\\mwcp-inputfi
le-n4mw7uw3\n\n----Output Files----\n\nfooconfigtest.txt    example output file\n                     5eb63bbbe01eeed093cb22bb8f5acdc3\n"
}
```


### Python API

`mwcp_api_example.py` demonstrates how to use the python API:

```python
#!/usr/bin/env python
"""
Simple example to demonstrate use of the API provided by DC3-MWCP framework.
"""

# first, import mwcp
import mwcp

# create an instance of the Reporter class
reporter = mwcp.Reporter()
"""
The mwcp.Reporter object is the primary DC3-MWCP framework object, containing most input and output data
and controlling execution of the parser modules.
"""

# register a directory containing parsers
mwcp.register_parser_directory(r'C:\my_parsers')

# view available parsers
print(mwcp.get_parser_descriptions())

# run the dummy config parser, view the output
reporter.run_parser("foo", "README.md")

# alternate, run on provided buffer:
reporter.run_parser("foo", data="lorem ipsum")

print(reporter.pprint(reporter.metadata))

# access output files
for filename in reporter.outputfiles:
    print("%s: %i bytes" % (reporter.outputfiles[filename]['path'],
                            len(reporter.outputfiles[filename]['data'])))
```


## Updates

DC3-MWCP code updates are implemented to be backwards compatible.

One exception to backwards compatibility is when new attributes are amended to previously existing
fields. An example of this is the MD5 entry being amended to the 'outputfile' field. When attribute
additions like this are made, it causes a backwards compatibility conflict with test cases. If
`test.py` is being used to manage regression tests, the amended attributes can cause previously
passing test cases to fail. To resolve this issue, work in an environment where parsers are in a known
good state and run the command `test.py -ua` to update all test cases. The newly generated test
cases will include the updated field values.

## Schema

One of the major goals of DC3-MWCP is to standardize output for malware configuration parsers, making the data
from one parser comparable with that of other parsers. This is achieved by establishing a schema of
standardized fields that represent the common malware attributes seen across malware families. To see the
list of standardized fields and their definitions, see `tool.py -k` or mwcp/resources/fields.json.

It is acknowledged that a set of generic fields will often not be adequate to capture the nuances of
individual malware families. To ensure that malware family specific attributes are appropriately captured
in parser output, the schema includes an "other" field which supports arbitrary key-value pairs. Information
not captured in the abstract standardized fields is captured through this mechanism.

Duplication of data items is encouraged both to provide additional family specific context and to
simplify access of data through both composite fields and individual fields. The DC3-MWCP framework extracts
individual items reported in composite fields to the degree possible. For example, the address in a url
will be extracted automatically by DC3-MWCP.

See mwcp/resources/fields.txt for additional explanation.


## Helper Utilities
MWCP comes with a few helper utilities (located in `mwcp.utils`) that may become useful for parsing malware files.

- `pefileutils` - Provides helper functions for common routines done with the pefile library. (obtaining or checking for exports, imports, resources, sections, etc.)
- `custombase64` - Provides functions for base64 encoding/decoding data with a custom alphabet.
- `construct` - Provides extended functionality to the [construct](construct.readthedocs.io) library.
    - This library has replaced the `enstructured` library originally found in the resources directory.
    - Please follow [this tutorial](docs/construct.ipynb) for migrating from `enstructured` to `construct`.
