# Parser Development Guide

This guide seeks to explain how to develop parsers for DC3-MWCP.

Please also review the [Python Style Guide](PythonStyleGuide.md). There is the expectation that parsers and parser updates will abide by these guidelines.


- [Steps](#steps)
- [Example Parser](#example-parser)
- [Error Handling](#error-handling)
- [Raising UnableToParse error](#raising-unabletoparse-error)
- [Passing Identify Results](#passing-identify-results)
- [Using The Construct Library](#using-the-construct-library)
- [Tech Anarchy Bridge](#tech-anarchy-bridge)
- [Parser Development Tips](#parser-development-tips)

### Guides
- [Parser Development](ParserDevelopment.md)
- [Parser Components](ParserComponents.md)
- [Parser Installation](ParserInstallation.md)
- [Parser Testing](ParserTesting.md)
- [Python Style Guide](PythonStyleGuide.md)


## Steps

To create a simple parser the high level step are:

1. [Install DC3-MWCP](../README.md#install)
    - If you plan to contribute your parser back to DC3-MWCP, you can install in "development" mode and
    place your parser directly into DC3-MWCP's "parsers" directory.
1. Create a directory to store your parsers.
1. Create a new python file in your parser directory.
    - The name of this file is usually the name of the malware family it is parsing, but could also be
      a category of components instead (e.g. `Archives.py`, `Decoys.py`, `Downloaders.py`).

1. Create classes that subclass `mwcp.Parser` where each class parses a particular component within that malware family or category. At a minimum, the class should have a `DESCRIPTION` attribute or it will be ignored.

    ```python
    # file: acme/SuperMalware.py
    from mwcp import Parser


    class Implant(Parser):
        DESCRIPTION = 'SuperMalware Implant'


    class Downloader(Parser):
        DESCRIPTION = 'SuperMalware Downloader'

    ```

1. Implement the `identify()` function for each class. This function accepts a [FileObject](ParserComponents.md#fileobject) object and must return a boolean indicating if
the parser can process the given file. Since the DC3-MWCP parser should only be run on a file that has already been identified using an external method like YARA, we know that the files being passed to it will either be files that matched the signature or files that were extracted by another parser in the same family. Therefore, this function only needs to be able to distinguish itself from the other parsers in the family. (This function will always return True if not implemented.)

    ```python
    # file: acme/SuperMalware.py
    from mwcp import Parser


    class Implant(Parser):
        DESCRIPTION = 'SuperMalware Implant'

        @classmethod
        def identify(cls, file_object):
            return file_object.pe and file_object.pe.is_exe()


    class Downloader(Parser):
        DESCRIPTION = 'SuperMalware Downloader'

        @classmethod
        def identify(cls, file_object):
            return file_object.pe and file_object.pe.is_dll()

    ```

1. Implement the `run()` function for each class. This function will parse identified files for configuration data as well as extract and dispatch any embedded files for further processing.

    ```python
    # file: acme/SuperMalware.py
    from mwcp import Parser


    class Implant(Parser):
        DESCRIPTION = 'SuperMalware Implant'

        @classmethod
        def identify(cls, file_object):
            return file_object.pe and file_object.pe.is_dll()

        def run(self):
            """parsing goes here"""


    class Downloader(Parser):
        DESCRIPTION = 'SuperMalware Downloader'

        @classmethod
        def identify(cls, file_object):
            return file_object.pe and not file_object.pe.is_dll()

        def run(self):
            """parsing goes here"""

    ```

1. See the [Parser Component Guide](ParserComponents.md) for more information.
1. See the [Parser Testing Guide](ParserTesting.md) for creating test cases for your parser.
1. See the [Parser Installation Guide](ParserInstallation.md) for installing your parser into DC3-MWCP.


## Example Parser

The following is provided as an example that may be used as a template.

```python
"""
MWCP parser for SuperMalware malware family.
"""
import os

from mwcp import Parser, FileObject, metadata


class Trojan(Parser):
    DESCRIPTION = 'SuperMalware Implant'

    MAGIC = b'\x00IM\x01A\x02TROJAN'

    @classmethod
    def identify(cls, file_object):
        """
        Identify a SuperMalware Implant.

        :param file_object: dispatcher.FileObject object

        :return: Boolean value indicating if file is a Foo Trojan.
        """
        return file_object.pe and cls.MAGIC in file_object.file_data

    def run(self):
        """
        Extract metdata from Foo Trojan.
        """
        ip_address = self._extract_ip_address()
        self.report.add(metadata.C2Address(ip_address))


class Dropper(Parser):
    DESCRIPTION = 'SuperMalware Dropper'

    IMPLANT_INDICATOR = b'ISTOREDMYIMPLANTHERE:'

    @classmethod
    def identify(cls, file_object):
        """
        Identify a SuperMalware Dropper.

        :param file_object: dispatcher.FileObject object

        :return: Boolean value indicating if file is a Foo Trojan.
        """
        return file_object.pe and file_object.pe.is_dll() and file_object.name.endswith('FooD.dll')

    def run(self):
        """
        Extract metadata and implant from SuperMalware Dropper.
        """
        # Decrypt and report implant.
        key = self._extract_rc4_key(self.file_object.data)
        if key:
            self.logger.info('Found RC4 key.')
            # Report key.
            self.report.add(metadata.EncryptionKey(key, algorithm="rc4"))

            # Decrypt and dispatch implant.
            implant_data = self._decrypt_implant(key, self.file_object.data)
            if implant_data:
                implant_file_object = FileObject(implant_data)
                self.dispatcher.add(implant_file_object)
        else:
            self.logger.warning('Unable to find RC4 key!')
```


## Error Handling
If your parser detects an expected error during execution that it can recover from, it is recommended
to set a log message explaining the condition and continue execution.
(e.g. Parser can't extract the encryption key but can still report on some c2 addresses)

However, it is acceptable to bubble up/or raise an Exception which will be caught by the
framework in the case of an unexpected error. Usually, if the parser can continue to provide some meaningful output the
parser will return from run doing as much processing as possible. If the error is such that returning no
further data is possible and processing must cease immediately, then it is acceptable to raise an exception
(or let an existing exception flow up uncaught).

A parser should not perform any type of broad exception catching (unless you have a very good reason to).
If runtime causes an unexpected exception due to a bug in the parser or due to a new malware sample
that is in-compatible with the parser, we want that exception to be raised! This will allow
the framework to report the error that has occurred with a detailed traceback. Making it quicker and easier to determine
where and why the parser failed and fix it. If the exception gets suppressed by a generic log message
or hidden by returning `None` it will be very difficult to detect and catch these errors.

A raised exception in a Parser object will not stop the entire run.
The Dispatcher will catch and report your exception and then move onto the next dispatched file.

In no event should the parser module get additional external information or modify program execution.
For example, the parser should not seek to open alternate input files themselves nor should they call sys.exit().
To ensure portability, these actions are reserved for the framework.


## Raising UnableToParse error
The `mwcp.UnableToParse` exception can be thrown if a parser that has been correctly identified has failed to parse the file and you would like other parsers to be tried.
This can be useful if identification would require heavy computation that you do not want to run twice.

```python
from mwcp import Parser, UnableToParse, metadata


class Trojan(Parser):
    """Parser for the Foo Trojan."""
    DESCRIPTION = 'Foo Trojan'

    MAGIC = b'\x00IM\x01A\x02TROJAN'

    @classmethod
    def identify(cls, file_object):
        """
        Identify a Foo Trojan.

        :param file_object: dispatcher.FileObject object

        :return: Boolean value indicating if file is a Foo Trojan.
        """
        # Identify as much as possible.
        return file_object.pe and cls.MAGIC in file_object.file_data

    def run(self):
        """
        Extract metdata from Foo Trojan.
        """
        config = self._some_heavy_computation()
        if not config:
            # Oops, if we can't get the config data, this file is a false positive
            # and we want other component parsers to be tried.
            raise UnableToParse("Configuration not found. File was miss-identified.")

        self.report.add(metadata.C2Address(config.c2_address))
```


## Passing Identify Results
If the `identify()` function contains computationally heavy processing, it may be beneficial to
pass the produced results over to the `run()` function to avoid re-running it.
This can be done by returning extra arguments after the boolean result.
These extra arguments will then be unpacked and passed into the `run()` function if identification is successful.
(This is usually helpful to prevent having to redo regular expression searches.)

*NOTE: If providing extra arguments, you must ensure that the first entry in the returned tuple is a boolean.
Otherwise, the returned result will just be used to check its truthiness and not be passed into `run()`.*

*As well, the `run()` function's signature must accept the extra arguments.*

```python
# file: acme/SuperMalware.py
from mwcp import Parser


class Implant(Parser):
    DESCRIPTION = 'SuperMalware Implant'

    @classmethod
    def identify(cls, file_object):
        if file_object.pe and file_object.pe.is_exe():
            result = cls._some_heavy_computation(file_object)
            if result:
                return True, result  # passing along result so we don't have to recompute it.
        return False

    def run(self, result):  # ensure signature matches what can be returned from identify()
        self._using_result_to_continue_processing(result)
```


## Using The Construct Library
We have found that using the [construct](https://construct.readthedocs.io) library has greatly helped to organize
and simplify extracting configuration data. It helps to separate the act of extraction from the analysis of
the data itself. This makes the code easier to read and update. Construct has fully replaced our use
of the enstructured library.

Our usual strategy is:
1. For each component, we create a construct spec that defines how to retrieve and extract our wanted data.
    - Our extra helper utilities ([mwcp.utils.construct](../mwcp/utils/construct/helpers.py)) contains a `construct.Regex` and `construct.PEPointer` constructs, that make it easy to find a particular pointer within the malware code and trace it to the referenced data.
1. If the construct spec has some validation components (Regex, Const, OneOf, Check, etc.) the spec can also
be used in the `identify()` function.

For example:

```python
import os
import re

from mwcp import Parser, FileObject, metadata
from mwcp.utils import construct
from construct import this


class Dropper(Parser):
    """Parser for the Foo Trojan."""
    DESCRIPTION = 'Foo Dropper'

    CONFIG = construct.Struct(
        'c2_address' / construct.CString(),
        'key' / construct.Int32ul,
        'mutex' / construct.Bytes(5),
        'size' / construct.Int32ul,
        'encrypted_data' / construct.Bytes(this.size)
    )

    # Jumps to the location of the decryption call then dereferences and extract the
    # the config parameter.
    DECRYPT_CALL = construct.Struct(
        're' / construct.Regex(re.compile('''
                \x85\xC0                        # test  eax, eax
                \x75\x07                        # jne   0xb
                \x56                            # push  esi
                \x68(?P<config_offset>.{4})     # push  <config_offset>
                \xE8.{4}                        # call  process_config
            ''', re.DOTALL | re.VERBOSE),
                               config_offset=construct.Int32ul
                               ),
        'config' / construct.PEPointer(this.re.config_offset, CONFIG)
    )

    @classmethod
    def identify(cls, file_object):
        """
        Identify a Foo Dropper.

        :param file_object: dispatcher.FileObject object

        :return: Boolean value indicating if file is a Foo Trojan.
        """
        if not file_object.pe:
            return False
        try:
            cls.DECRYPT_CALL.parse(file_object.file_data, pe=file_object.pe)
            return True
        except construct.ConstructError:
            return False

    def run(self):
        """
        Extract metadata and implant from Foo Dropper.
        """
        # parse config
        info = self.DECRYPT_CALL.parse(self.file_object.data, pe=self.file_object.pe)
        config = info.config

        # report metadata
        self.report.add(metadata.C2Address(config.c2_address))
        self.report.add(metadata.Mutex(config.mutex))

        # decrypt implant.
        self.report.add(metadata.EncryptionKey(config.key, algorithm="xor"))
        implant_data = self._decrypt(config.key, config.encrypted_data)

        # dispatch implant to be picked up by another parser.
        self.dispatcher.add(FileObject(implant_data))
```


## Tech Anarchy Bridge

While DC3-MWCP does not include any malware parsers, it does include a bridge to enable use
of the parsers provided by Kev of [TechAnarchy/malwareconfig.com](http://kevthehermit.github.io/RATDecoders).
The purpose of this bridge is to execute the Tech Anarchy parsers, capture the output, and normalize
the fields. This bridge can be used to create simple DC3-MWCP modules which call the underlying
Tech Anarchy parsers. It is the responsibility of the user to ensure that field mappings are
correct, adjusting the bridge as necessary.

See [mwcp/resources/techanarchy_bridge.py](../mwcp/resources/techanarchy_bridge.py)

All Tech Anarchy parsers found within the `mwcp/resources/RATDecoders` folder will
automatically be available for use as a parser using the `TA.` prefix. (e.g. `TA.CyberGate`)

After executing the parser, check for issues in data mappings or format. Adjust the field mapping code of techanarchy_bridge.py accordingly. For example,
the following CyberGate specific condition was added to address malformed output in the original techanarchy parser:

```python
from mwcp import metadata

if scriptname == "CyberGate":
    report.add(metadata.Socket(
        address=data["Domain"].rstrip("|"), port=data["Port"].rstrip("|"), network_protocol="tcp", c2=True
    ))
else:
    report.add(metadata.Socket(
        address=data["Domain"], port=data["Port"], network_protocol="tcp", c2=True
    ))
```


## Parser Development Tips
- Standardized field mapping:
    - Let data type dictate field selection
    - Use most complete field possible
- Include additional context using the "Other" metadata element.
- Keep your parsers organized and maintainable! Each parser should only handle a single component and should dispatch all embedded files for other parsers to pick up.
- Stay portable:
    - Respect interfaces
    - Use common modules for dependencies
    - Maintain cross platform functionality: *nix and windows
- The parser should never try to write output files directly to the filesystem.
    - Either add `File` metadata element to the report or let the `Dispatcher` output it for you.
- Use [mwcp.utils.construct](construct.ipynb) to help organize your config structures.
