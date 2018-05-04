# Parser Development Guide

This guide seeks to explain how to develop parsers for DC3-MWCP.

Please also review the [Python Style Guide](http://svn.ia.lan/trac/IN_Dev_Repo/wiki/PythonStyleGuide). There is the expectation that parsers and parser updates will abide by these guidelines.


- [Steps](#steps)
- [Interfacing with the Reporter](#interfacing-with-the-reporter)
    - [Guidance on standardized fields](#guidance-on-standardized-fields)
- [Simple Example](#simple-example)
- [Dispatching Component Parsers](#dispatching-component-parsers)
- [Error Handling](#error-handling)
- [Logging](#logging)
- [Using The Construct Library](#using-the-construct-library)
- [Tech Anarchy Bridge](#tech-anarchy-bridge)
- [Parser Development Tips](#parser-development-tips)


## Steps

To create a simple parser the high level step are:

1. [Install DC3-MWCP](../README.md#install)
    - If you plan to contribute your parser back to DC3-MWCP, you can install in "development" mode and
    place your parser directly into DC3-MWCP's "parsers" directory.
1. Create a new python file in your parser directory.
    - The name of this file is usually the name of the malware family it is parsing.
    - You no longer need to append `_malwareconfigparser` to the end of the file name.

1. Create a new class that is a subclass of `mwcp.Parser`
    - Set the appropriate values for the constructor -- this data is used when listing the parsers in mwcp.

1. Implement the run function to start [interfacing with the Reporter](#interface-with-the-reporter).
1. See the [Testing Guide](Testing.md) for creating test cases for your parser.
1. See the [Parser Installation Guide](ParserInstallation.md) for installing your parser into DC3-MWCP.


## Interfacing with the Reporter

All control is handled by the `mwcp.Reporter` object which can be accessed from `self.reporter` from both `mwcp.Parser` and `mwcp.ComponentParser` classes.

You can access the original input malware file using `input_file` attribute to access the file as an instance of a `mwcp.FileObject`.

Add metadata using the `reporter.add_metadata(key, value)` function
    - `key` is the file name of the metadata item. This should be one of the standardized fields reported in [mwcp/resources/fields.json](../mwcp/resources/fields.json). (Hint: Run `mwcp-tool -k` to get a list of all fields.
    - `value` is the actual value to report.
        - For a "listofstrings" type, this is simply the string to report.
        - For a "listofstringtuples" type, this is a tuple or list.
        - For a "dictofstrings" type, this is a dictionary with string values.
    - Malware specific metadata that does not fit one of the standard fields can be added to the "other" field, passing in a dictionary containing the key:value pair for this custom metadata item.
    - All strings provided to the add_metadata function should be either unicode objects or utf8 encoded strings. If string values cannot be decoded as utf-8, they will be replaced.

You can manually report output files that are of interest to the user using the `output_file()` function.

The `managed_tempdir()` function can be used to access the temporary directory used by the reporter. You may use this to write out any files that need to be written to the filesystem. (e.g. to use an external utility)
    - However, if you are trying to temporarily write out the malware file to get a path, it is recommend to call
      `self.reporter.input_file.file_path` instead.
    - Everything in this temporary directory will be deleted when the framework exits.

#### Guidance on standardized fields

When possible, use the most comprehensive field possible. Ex. if you have an address and a tcp port, report the socketaddress instead of the address and port separately

 Subfields are parsed automatically. They can be reported, but it is not necessary. Ex. if you report a socketaddress, reporting the address and port is redundant and not necessary

Remember that the standardized fields are designed to encompass data in a standardized format, not necessarily to match exactly how data is encoded in the malware being analyzed. The "other" fields are designed to capture specimen and family specific nuances.


## Simple Example

Probably the best way to explain is to provide a simple example parser.

```python
# mwcp/parsers/foo.py

import os

from mwcp import Parser


class Foo(Parser):
    def __init__(self, reporter):
        Parser.__init__(
            self,
            description='example parser that works on any file',
            author='DC3',
            reporter=reporter
        )

    def run(self):

        # get input malware file
        input_file = self.reporter.input_file

        # standardized metadata
        self.reporter.add_metadata("url", "http://127.0.0.1")

        # demonstrate access to sample
        self.reporter.debug("size of inputfile is %i bytes" % (len(input_file.file_data)))

        # other, non-standardized metadata
        # also demonstrate use of pefile object
        if input_file.pe:
            self.reporter.add_metadata(
                "other", {"section0": input_file.pe.sections[0].Name.rstrip('\x00')})

        # demonstrate file output
        self.reporter.output_file("hello world", "fooconfigtest.txt", "example output file")

        # demonstrate use of file_name
        self.reporter.debug("operating on inputfile %s" % input_file.file_name)

        # demonstrate use of managed tempdir
        with open(os.path.join(self.reporter.managed_tempdir(), "footmp.txt"), "w") as f:
            f.write(
                "This is a temp file created in a directory that will be managed by the mwcp framework. \
                The directory will initially be empty, so there is no worry about name collisions. \
                The directory is deleted after this module run ends, unless tempcleanup is disabled."
            )

        # demonstrate getting a file stream of the input file
        with input_file as fo:
            fo.seek(10)
            data = fo.read(100)

        # demonstrate getting a file path of the input file
        # (although, prefer using the ".file_data" or a file stream if you can)
        data = some_external_utility(input_file.file_path)


```

## Dispatching Component Parsers
The above example works for simple cases. However, when you run into malware containing multiple components
embedded within each other with multiple variations, it can easily grow your parser to an unmanageable size.

DC3-MWCP comes with a Dispatcher model that allows you to organize your code based on their individual components
and variations.

For documentation please read: [Dispatcher Parser Development](DispatcherParserDevelopment.md).

*It is recommend you use the dispatcher model even for simple parsers to future proof your parser.*


## Error Handling
If your parser detects an expected error during execution that it can recover from, it is recommended
to set a debug message explaining the condition and continue execution.
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

When using the [dispatcher model](#DispatcherParserDevelopment.md), a raised exception in a Component parser
will not stop the entire run. The Dispatcher will catch and report your exception and then move onto the next
dispatched file.

In no event should the parser module get additional external information or modify program execution.
For example, parser should not seek to open alternate input files themselves nor should they call sys.exit().
To ensure portability, these actions are reserved for the framework.


## Logging
The `mwcp.Reporter` object contains a `debug()` function that can be used to report info/debug message to the user.

Attempts to `print()` will be captured and sent to the debug messages but `debug()` is the preferred method of reporting debug messages.


## Using The Construct Library
We have found that using the [construct](https://construct.readthedocs.io) library has greatly helped to organize
and simplify extracting configuration data. It helps to separate the act of extraction from the analysis of
the data itself. This makes the code easier to read and update. Construct has fully replaced our use
of the enstructured library.

Our usual strategy is:
1. Create a parser using the [dispatcher model](#DispatcherParserDevelopment.md).
1. For each component, we create construct spec that defines how to retrieve and extract our wanted data.
    - Our extra helper utilities ([mwcp.utils.construct](../mwcp/utils/construct/helpers.py)) contains a `construct.Regex` and `construct.PEPointer` constructs, that make it easy to find a particular pointer within the malware code and trace it to the referenced data.
1. If the construct spec has some validation components (Regex, Const, OneOf, Check, etc.) the spec can also
be used in the `identify()` function.

For example:

```python
import os

from mwcp import Parser, ComponentParser, FileObject, Dispatcher
from mwcp.utils import construct
from construct import this


class FooDropper(ComponentParser):
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
        'insn' / construct.Regex(
            '\x85\xC0\x75\x07\x56\x68(?P<param_offset>.{4})\xE8.{4}',
            param_offset=construct.Int32ul
        ),
        'config' / construct.PEPointer(this.insn.param_offset, CONFIG)
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
        info = self.DECRYPT_CALL.parse(self.file_object.file_data, pe=self.file_object.pe)
        config = info.config

        # report metadata
        self.reporter.add_metadata('c2_address', config.c2_address)
        self.reporter.add_metadata('mutex', config.mutex)

        # decrypt implant.
        self.reporter.add_metadata('key', hex(config.key))
        implant = self._decrypt(key, config.encrypted_data)

        # dispatch implant to be picked up by FooTrojan component parser.
        self.dispatcher.add_to_queue(FileObject(implant, self.reporter))


# Entry point parser that runs all of the component parsers.
class Foo(Dispatcher, Parser):
    def __init__(self, reporter):
        Parser.__init__(
            self,
            description='module for testing/examples',
            author='ACME',
            reporter=reporter
        )
        Dispatcher.__init__(
            self,
            reporter=reporter,
            parsers=[FooCarrier, FooDropper, FooTrojan]
        )
```


## Tech Anarchy Bridge

While DC3-MWCP does not include any malware parsers, it does include a bridge to enable use
of the parsers provided by Kev of techanarchy.net/malwareconfig.com. The purpose
of this bridge is to execute the Tech Anarchy parsers, capture the output, and normalize
the fields. This bridge can be used to create simple DC3-MWCP modules which call the underlying
Tech Anarchy parsers. It is the responsibility of the user to ensure that field mappings are
correct, adjusting the bridge as necessary.

See [mwcp/resources/techanarchy_bridge.py](../mwcp/resources/techanarchy_bridge.py)


To create an mwcp parser module, run techanarchy_bridge.py as a script with the techanarchy module name as the only argument:

        mwcp/resources/techanarchy_bridge.py CyberGate
This will create a `mwcp.Parser` module that should be placed in the parsers directory.

After executing the parser, check for issues in data mappings or format. Adjust the field mapping code of techanarchy_bridge.py accordingly. For example,
the following CyberGate specific condition was added to address malformed output in the original techanarchy parser:

```python
if scriptname == "CyberGate":
    reporter.add_metadata("c2_socketaddress", (data['Domain'].rstrip("|"), data['Port'].rstrip("|"), "tcp"))
else:
    reporter.add_metadata("c2_socketaddress", (data['Domain'], data['Port'], "tcp"))
```


## Parser Development Tips
- Standardized field mapping:
    - Let data type dictate field selection
    - Use most complete field possible
- Include additional context using the "other" field
- Use the [dispatcher model](#DispatcherParserDevelopment.md) to keep your parser
  organized and maintainable!
- Let DC3-MWCP manage your temp files: see reporter.managed_tempdir()
- Stay portable:
    - Respect interfaces
    - Use common modules for dependencies
    - Maintain cross platform functionality: *nix and windows
- Do not use parser arguments unless absolutely necessary
- The parser should never try to write output files directly to the filesystem.
    - Use the Reporter's `output_file()` or let the `mwcp.Dispatcher` output it for you.
- Use [mwcp.utils.construct](construct.ipynb) to help organize your config structures.
