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
- [No-install Method](#no-install-method)
- [DC3-Kordesii Support](#dc3-kordesii-support)
- [Testing](#testing)
- [Usage](#usage)
    - [CLI Tool](#cli-tool)
    - [REST API](#rest-api)
    - [Python API](#python-api)
- [Updates](#updates)
- [Schema](#schema)
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

## No-install Method
You can also use MWCP without installing using the *mwcp-\*.py* scripts.
However, you will need to manually install all the dependencies.
You can find the dependencies listed in the `setup.py` file.

*This method is not recommended and is only here for backwards compatibility.*

```
python mwcp-tool.py -h
```

## DC3-Kordesii Support
DC3-MWCP optionally supports [DC3-Kordesii](https://github.com/Defense-Cyber-Crime-Center/kordesii)
if it is installed. This will allow you to run any DC3-Kordesii decoder from the
`mwcp.FileObject` object with the `run_kordesii_decoder` function.

<!-- Uncomment if we ever get published in PyPi
You can install DC3-Kordesii along with DC3-MWCP by adding `[kordesii]` to your appropriate install command:
```
pip install mwcp[kordesii]
pip install ./DC3-MWCP[kordesii]
pip install -e ./DC3-MWCP[kordesii]
```
-->


## Testing
DC3-MWCP uses [tox](https://tox.readthedocs.io) with [pytest](https://pytest.org) to test the core code
and parsers. These libraries will be installed when you install DC3-MWCP.
To run all tests on Python 2.7 and 3.6 run the `tox` command after installation.

```console
> tox
GLOB sdist-make: C:\dev\DC3_MWCP\setup.py
py27 inst-nodeps: C:\dev\DC3_MWCP\.tox\dist\mwcp-1.2.0.zip
py27 installed: attrs==17.4.0,bottle==0.12.13,certifi==2018.4.16,chardet==3.0.4,colorama==0.3.9,construct==2.8.12,funcsigs==1.0.2,future==0.16.0,idna==2.6,Jinja2==2.10,MarkupSafe==1.0,mock==2.0.0,more-itertools==4.1.0,mwcp==1.2.0,pbr==4.0.2,pefile==2017.11.5,pluggy==0.6.0,py==1.5.3,pytest==3.5.0,pytest-console-scripts==0.1.4,pytest-mock==1.9.0,requests==2.18.4,six==1.11.0,tox==3.0.0,urllib3==1.22,virtualenv==15.2.0
py27 runtests: PYTHONHASHSEED='155'
py27 runtests: commands[0] | pytest --doctest-modules
============================= test session starts =============================
platform win32 -- Python 2.7.14, pytest-3.5.0, py-1.5.3, pluggy-0.6.0
rootdir: C:\dev\DC3_MWCP, inifile: tox.ini
plugins: mock-1.9.0, console-scripts-0.1.4
collected 59 items

mwcp\utils\construct\construct_html.py .                                 [  1%]
mwcp\utils\construct\helpers.py .........................                [ 44%]
mwcp\utils\construct\windows_enums.py ....                               [ 50%]
mwcp\utils\construct\windows_structures.py .                             [ 52%]
tests\test_cli.py .......                                                [ 64%]
tests\test_custombase64.py ...                                           [ 69%]
tests\test_dispatcher.py .....                                           [ 77%]
tests\test_parser_registry.py ..                                         [ 81%]
tests\test_reporter.py ...........                                       [100%]

========================== 59 passed in 8.30 seconds ==========================
py36 inst-nodeps: C:\dev\DC3_MWCP\.tox\dist\mwcp-1.2.0.zip
py36 installed: attrs==17.4.0,bottle==0.12.13,certifi==2018.4.16,chardet==3.0.4,colorama==0.3.9,construct==2.8.12,future==0.16.0,idna==2.6,Jinja2==2.10,MarkupSafe==1.0,mock==2.0.0,more-itertools==4.1.0,mwcp==1.2.0,pbr==4.0.2,pefile==2017.11.5,pluggy==0.6.0,py==1.5.3,pytest==3.5.0,pytest-console-scripts==0.1.4,pytest-mock==1.9.0,requests==2.18.4,six==1.11.0,tox==3.0.0,urllib3==1.22,virtualenv==15.2.0
py36 runtests: PYTHONHASHSEED='155'
py36 runtests: commands[0] | pytest
============================= test session starts =============================
platform win32 -- Python 3.6.3, pytest-3.5.0, py-1.5.3, pluggy-0.6.0
rootdir: C:\dev\DC3_MWCP, inifile: tox.ini
plugins: mock-1.9.0, console-scripts-0.1.4
collected 28 items

tests\test_cli.py .......                                                [ 25%]
tests\test_custombase64.py ...                                           [ 35%]
tests\test_dispatcher.py .....                                           [ 53%]
tests\test_parser_registry.py ..                                         [ 60%]
tests\test_reporter.py ...........                                       [100%]

========================== 28 passed in 6.33 seconds ==========================
___________________________________ summary ___________________________________
  py27: commands succeeded
  py36: commands succeeded
  congratulations :)
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

see ```mwcp parse -h``` for full set of options


### REST API

DC3-MWCP can be used as a web service. The REST API provides two commonly used functions:

* ```/run_parser/<parser>``` -- executes a parser on uploaded file
* ```/descriptions``` -- provides list of available parsers

To use, first start the server by running:
```console
> mwcp serve
```

Then you can either use an HTTP client to create REST requests.

Using cURL:
```console
> curl --form data=@README.md http://localhost:8080/run_parser/foo
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
    "output_text": "\n----Standard Metadata----\n\nurl                  http://127.0.0.1\naddress              127.0.0.1\n\n----Debug----\n\nsize of inputfile
is 7128 bytes\noutputfile: fooconfigtest.txt\noperating on inputfile C:\\Users\\JOHN.DOE\\AppData\\Local\\Temp\\mwcp-managed_tempdir-pk0f12oh\\mwcp-inputfi
le-n4mw7uw3\n\n----Output Files----\n\nfooconfigtest.txt    example output file\n                     5eb63bbbe01eeed093cb22bb8f5acdc3\n"
}
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


# create an instance of the Reporter class
reporter = mwcp.Reporter()
"""
The mwcp.Reporter object is the primary DC3-MWCP framework object, containing most input and output data
and controlling execution of the parser modules.
"""

# run the dummy config parser, view the output
reporter.run_parser("foo", "README.md")

# alternate, run on provided buffer:
reporter.run_parser("foo", data="lorem ipsum")

reporter.print_report()
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


## Updates

DC3-MWCP code updates are implemented to be backwards compatible.

One exception to backwards compatibility is when new attributes are amended to previously existing
fields. An example of this is the MD5 entry being amended to the 'outputfile' field. When attribute
additions like this are made, it causes a backwards compatibility conflict with test cases. If
`mwcp test` is being used to manage regression tests, the amended attributes can cause previously
passing test cases to fail. To resolve this issue, work in an environment where parsers are in a known
good state and run the command `mwcp test -u` to update all test cases. The newly generated test
cases will include the updated field values.

## Schema

One of the major goals of DC3-MWCP is to standardize output for malware configuration parsers, making the data
from one parser comparable with that of other parsers. This is achieved by establishing a schema of
standardized fields that represent the common malware attributes seen across malware families. To see the
list of standardized fields and their definitions, see [fields.json](mwcp/config/fields.json).

It is acknowledged that a set of generic fields will often not be adequate to capture the nuances of
individual malware families. To ensure that malware family specific attributes are appropriately captured
in parser output, the schema includes an "other" field which supports arbitrary key-value pairs. Information
not captured in the abstract standardized fields is captured through this mechanism.

Duplication of data items is encouraged both to provide additional family specific context and to
simplify access of data through both composite fields and individual fields. The DC3-MWCP framework extracts
individual items reported in composite fields to the degree possible. For example, the address in a url
will be extracted automatically by DC3-MWCP.

See [fields.txt](mwcp/config/fields.txt) for additional explanation.


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
 