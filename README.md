# DC3-MWCP
DC3 Malware Configuration Parser (DC3-MWCP) is a framework for parsing configuration information from malware.
The information extracted from malware includes items such as addresses, passwords, filenames, and
mutex names. A parser module is usually created per malware family.
DC3-MWCP is designed to help ensure consistency in parser function and output, ease parser development,
and facilitate parser sharing. DC3-MWCP supports both analyst directed analysis and
large-scale automated execution, utilizing either the native python API, a REST API, or a provided
command line tool. DC3-MWCP is authored by the Defense Cyber Crime Center (DC3).

## Dependencies

DC3-MWCP requires python 2.7 (the core components should operate on python 2.6).

`mwcp-client.py` requires the requests module.

### Recommended Modules
The following modules are recommended as they are often used in parsers
- pefile
- yara-python
- pyCrypto
- pydasm

## Installation

Use setup.py to perform a setuptools install or build a distributable package. For 
example, download the source tree and run `setup.py install`.

DC3-MWCP can also be used by merely downloading the source tree and executing the mwcp utilities.

### Parser and Resource installation

Both parsers and external resources (dependencies) are installed separately from DC3-MWCP.

Both parser modules and other resources are imported using standard python import resolution methods.
Therefore, to ensure a parser or resource is available, they simply need to be available in python's
module search path. When
searching for parser modules, DC3-MWCP considers modules matching the pattern *_malwareconfigparser as possible
modules.

Assuming a setup.py install was performed for DC3-MWCP, using a setup.py install for modules and other
resources is also advised. 

To ease execution with a manual install, DC3-MWCP adds the parserdir and resourcedir
to python's path (see mwcp-tool.py options or malwareconfigreporter constructor). Parsers and resources
can simply be placed in these directories. 

It is recommended that parser modules be shared in their own distribution packages, allowing for either
a setup.py install or manual installation by users.

### Updates

DC3-MWCP code updates are implemented to be backwards compatible. 

One exception to backwards compatibility is when new attributes are amended to previously existing 
fields. An example of this is the MD5 entry being amended to the 'outputfile' field. When attribute 
additions like this are made, it causes a backwards compatibility conflict with test cases. If 
`mwcp-test.py` is being used to manage regression tests, the amended attributes can cause previously
passing test cases to fail. To resolve this issue, work in an evironment where parsers are in a known 
good state and run the command `mwcp-test.py -ua` to update all test cases. The newly generated test
cases will include the updated field values.

## Schema

One of the major goals of DC3-MWCP is to standardize output for malware configuration parsers, making the data
from one parser comparable with that of other parsers. This is achieved by establishing a schema of 
standardized fields that represent the common malware attributes seen across malware families. To see the
list of standardized fields and their definitions, see `mwcp-tool.py -k` or mwcp/resources/fields.json.

It is acknowledged that a set of generic fields will often not be adequate to capture the nuances of
individual malware families. To ensure that malware family specific attributes are appropriately captured
in parser output, the schema includes an "other" field which supports arbitrary key-value pairs. Information
not captured in the abstract standardized fields is captured through this mechanism.

Duplication of data items is encouraged both to provide additional family specific context and to
simplify access of data through both composite fields and individual fields. The DC3-MWCP framework extracts
individual items reported in composite fields to the degree possible. For example, the address in a url
will be extracted automatically by DC3-MWCP.

See mwcp/resources/fields.txt for additional explanation.


## Use
DC3-MWCP is designed to allow easy development and use of malware config parsers. DC3-MWCP is also designed to ensure
that these parsers are scalable and that DC3-MWCP can be integrated in other systems.

Most automated processing systems will use a condition, such as a yara signature match, to trigger execution
of an DC3-MWCP parser.

There are 3 options for integration of DC3-MWCP:
- python API: mwcp_api_example.py
- Rest API based on wsgi/bottle: mwcp-server.py, mwcp-client.py
- CLI: mwcp-tool.py

DC3-MWCP also includes a utility for test case generation and execution: mwcp-test.py

### Python API

mwcp_api_example.py demonstrates how to use the python API:

```python
#!/usr/bin/env python
'''
Simple example to demonstrate use of the API provided by DC3-MWCP framework.
'''

#first, import the malwareconfigreporter class
from mwcp.malwareconfigreporter import malwareconfigreporter

#create an instance of the malwareconfigreporter class
reporter = malwareconfigreporter()
'''
The malwareconfigreporter object is the primary DC3-MWCP framework object, containing most input and output data
and controlling execution of the parser modules.

The most common parameters to provide are parserdir and resourcedir, depending upon your installation.
'''
#view location of resource and parser directories
print reporter.resourcedir
print reporter.parserdir

#view available parsers
print reporter.get_parser_descriptions()

#run the dummy config parser, view the output
reporter.run_parser("foo", "README.md")

#alternate, run on provided buffer:
reporter.run_parser("foo", data = "lorem ipsum")

print reporter.pprint(reporter.metadata)

#access output files
for filename in reporter.outputfiles:
    print("%s: %i bytes" % (reporter.outputfiles[filename]['path'], len(reporter.outputfiles[filename]['data'])))

```

### REST API

The REST API provides two commonly used functions:

* ```/run_parser/<parser>``` -- executes a parser on uploaded file
* ```/descriptions``` -- provides list of available parsers

mwcp-client.py and the following curl commands demonstrate how to use this web service:
```sh
curl --form data=@README.md http://localhost:8080/run_parser/foo
curl http://localhost:8080/descriptions
```

bottle (bottlepy.org) is required for the server. The bottle provided web server
or another wsgi can be used.

### CLI tool

mwcp-tool.py provides functionality to run parsers on files:

```sh
mwcp-tool.py -p foo README.md
```

see ```mwcp-tool.py -h``` for full set of options


## Parser Development

The high level setps for module development are:

- Create new *_malwareconfigparser module
- Subclass malwareconfigparser
- Implement run()
- Use reporter object
  - Access malware sample
  - Report metadata
  - etc.

foo_malwareconfigparser.py is provided as an example and may be used as a template:


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

### Parser Development Tips
- Standardized field mapping:
  - Let data type dictate field selection
  - Use most complete field possible
- Include additional context using other fields
- Output files/artifacts if they are relevant
- Let DC3-MWCP manage your temp files: see reporter.managed_tempdir()
- Do not bleed data: use instance variables instead of class variables
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








