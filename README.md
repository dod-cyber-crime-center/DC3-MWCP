# DC3-MWCP
DC3 Malware Configuration Parser (DC3-MWCP) is a framework for parsing configuration information from malware.
The information extracted from malware includes items such as addresses, passwords, filenames, and
mutex names. A parser module is usually created per malware family.
DC3-MWCP is designed to help ensure consistency in parser function and output, ease parser development,
and facilitate parser sharing. DC3-MWCP supports both analyst directed analysis and
large-scale automated execution, utilizing either the native python API, a REST API, or a provided
command line tool. DC3-MWCP is authored by the Defense Cyber Crime Center (DC3).

## Install

```
pip install mwcp
```

For a development mode use the `-e` flag to install in editable mode:
```
git clone https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP.git
pip install -e ./mwcp
```

Alternatively, you can use MWCP without installing using the *mwcp-\*.py* scripts.
However, you will need to manually install the dependencies.

*NOTE: This method is not recommend and is only here for backwards compatibility.*

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

# first, import the malwareconfigreporter class
from mwcp.malwareconfigreporter import malwareconfigreporter

# create an instance of the malwareconfigreporter class
reporter = malwareconfigreporter()
"""
The malwareconfigreporter object is the primary DC3-MWCP framework object, containing most input and output data
and controlling execution of the parser modules.

The most common parameters to provide are parserdir and resourcedir, depending upon your installation.
"""
# view location of resource and parser directories
print(reporter.resourcedir)
print(reporter.parserdir)

# view available parsers
print(reporter.get_parser_descriptions())

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
passing test cases to fail. To resolve this issue, work in an evironment where parsers are in a known
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

<!-- TODO: move this to its own doc file -->
## Parser Development

The high level steps for module development are:

- Create new *_malwareconfigparser module
- Subclass malwareconfigparser
- Implement run()
- Use reporter object
  - Access malware sample
  - Report metadata
  - etc.

`foo_malwareconfigparser.py` is provided as an example and may be used as a template:


```python
import os
from mwcp.malwareconfigparser import malwareconfigparser

class Foo(malwareconfigparser):  
    def __init__(self, reporter = None):
        malwareconfigparser.__init__(self,
            description = 'example parser that works on any file',
            author = 'DC3',
            reporter = reporter
            )

    def run(self):
            
        #standardized metadata
        self.reporter.add_metadata("url", "http://127.0.0.1")

        #demonstrate access to sample
        self.reporter.debug("size of inputfile is %i bytes" % (len(self.reporter.data)))
        
        #other, non-standardized metadata
        #also demonstrate use of pefile object
        if self.reporter.pe:
            self.reporter.add_metadata("other", {"section0": self.reporter.pe.sections[0].Name.rstrip('\x00')})

        #demonstarte file output
        self.reporter.output_file("hello world", "fooconfigtest.txt", "example output file")

        #demonstrate use of filename()
        self.reporter.debug("operating on inputfile %s" % self.reporter.filename())

        #demonstrate use of managed tempdir
        with open(os.path.join(self.reporter.managed_tempdir(), "footmp.txt"), "w") as f:
            f.write("This is a temp file created in a directory that will be managed by the mwcp framework. \
                The directory will initially be empty, so there is no worry about name collisions. \
                The directory is deleted after this module run ends, unless tempcleanup is disabled.")

```

### Parser Installation
To make a parser available for use, place it in a directory with the name `<name>_malwareconfigparser.py` (Where `<name>` is a unique name you provide. Usually the name of the malware family.)
Then pass the directory containing your parsers to the mwcp tool being used.
```
mwcp-tool --parserdir=C:\my_parsers -p <name> <input_file>
# OR
mwcp-server --parserdir=C:\my_parsers
```

If no parser directory is specified it will default to the parser directory that comes with this python package.
Usually located in site-package. (e.g. C:\Python27\Lib\site-packages\mwcp\parsers)

### Parser Development Tips
- Standardized field mapping:
  - Let data type dictate field selection
  - Use most complete field possible
- Include additional context using other fields
- Output files/artifacts if they are relevant
- Let DC3-MWCP manage your temp files: see reporter.managed_tempdir()
- Stay portable:
  - Respect interfaces
  - Use common modules for dependencies
  - Maintain cross platform functionality: *nix and windows
- Do not use parser arguments unless absolutely necessary

### Tech Anarchy Bridge

While DC3-MWCP does not include any malware parsers, it does include a bridge to enable use
of the parsers provided by Kev of techanarchy.net/malwareconfig.com. The purpose
of this bridge is to execute the Tech Anarchy parsers, capture the output, and normalize
the fields. This bridge can be used to create simple DC3-MWCP modules which call the underlying
Tech Anarchy parsers. It is the responsibility of the user to ensure that field mappings are
correct, adjusting the bridge as necessary.

See mwcp/resources/techanarchy_bridge.py
