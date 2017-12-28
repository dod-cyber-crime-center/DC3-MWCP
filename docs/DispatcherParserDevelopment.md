# Dispatcher Parser Development

## How the Dispatcher Works
A Dispatcher model allows for more robust file identification, reporting, and objectifying content to ease maintenance.

The Dispatcher works by running a queue of input files on a list of registered parsers.
Each parser identifies if it can parse the given file. If a parser identifies the file, the dispatcher
will output the file to the mwcp reporter and run that parser. The parser can then report any metadata as well as extract and place any
embedded files onto the queue for further processing.

This method allows you to separate each component (e.g. carrier, dropper, installer, implant) into their
own class. Focusing on each part separately.


## Initializing a MWCP Dispatch parser
A config parser can be written using the Dispatcher model by having the parser inherit from both the
`mwcp.Parser` and `mwcp.Dispatcher` class. After which you will then need to run the `__init__` functions
for both classes.

The `Dispatcher.__init__` function accepts a list of parsers that it will use to process dispatched files
it receives on the queue. The order of this list is the order that the dispatcher will attempt to
identify valid parsers.

By default, only the first parser within the list that identifies the file will be run.
You can set the `greedy` keyword argument to `True` in `Dispatcher.__init__` to make make the dispatcher run
on all parsers that have identified it.

By default, if no parsers have identified the file, it is reported as an "Unidentified file" using the `Dispatcher.UnidentifiedFile` parser.
You can change this default to your own parser by setting the `default` keyword argument in `Dispatcher.__init__`.

If you would like to change how the the dispatcher determines which parser to run, you can can overwrite the `Dispatcher._identify_file()` function.

```python
from mwcp import Dispatcher, Parser

class Foo(Dispatcher, Parser):
    def __init__(self, reporter):
        Parser.__init__(
            self,
            description='module for testing/examples',
            author='CGS',
            reporter=reporter
        )
        Dispatcher.__init__(
            self,
            reporter=reporter,
            parsers=[FooCarrier, FooDropper, FooTrojan]
        )
```

## Creating Component Parsers
The Component Parsers are created by inheriting from `mwcp.ComponentParser`. These parsers are designed to identify and parse a component of the malware family. (e.g. carrier, loader, dropper, etc.)

The parser should not overwrite the `__init__` function, unless there are extra instance variables you
need to initialize. (If so, make sure you still call super to inialize `ParserBase`).

The parser class should have a `DESCRIPTION` variable set. This is used as the file description for identified files if the description has not been set when the file was added to the dispatch queue.

It's a good idea to also store your constant variables (signatures, regular expressions, structs, etc.) specific to this file as a class variable. Theses constants can be access from any function using
`self.MY_CONSTANT` or `cls.MY_CONSTANT`.

```python
from mwcp import ComponentParser

class FooDropper(ComponentParser):
    """Parser for the Foo Trojan."""
    DESCRIPTION = 'Foo Dropper'

    IMPLANT_INDICATOR = b'ISTOREDMYIMPLANTHERE:'
```

### Identifying
The parser must at least implement the `identify` function. *(Note: This is a class method not an instance method)* This function should return a boolean indicating if the given `file_object` can be parsed by this parser. Since the MWCP parser should only be run on a file that has already been identified using an external method like YARA, we know that the files being passed to it will either be files that matched the signature or files that were extracted by another parser in the same family. Therefore, this function only needs to be able to distinguish itself from the other parsers. For example, if the dropper is the only dll you could return `file_object.pe and file_object.pe.is_dll()`.

```python
    @classmethod
    def identify(cls, file_object):
        """
        Identify a Foo Dropper

        :param file_object: dispatcher.FileObject object

        :return: Boolean value indicating if file is a Foo Trojan.
        """
        return file_object.pe and file_object.pe.is_dll() and self.file_object.file_name.endswith('FooD.dll')
```

### Running
If the file has been successfully identified, the dispatcher will run the the `run()` function.
*(If this function is not implemented, the dispatcher will only output the file with the parser's `DESCRIPTION`)*
Within this function you can access the file with `self.file_object` which is an instance of `mwcp.FileObject`. This file object contains attributes about this file (`pe`, `file_data`, `file_name`, etc.)
that can be used to extract metadata and embedded components.

If you have a new file to extract, you can place that file onto the dispatcher queue by running:

```python
embedded_file = FileObject(embedded_data, reporter=self.reporter)
self.dispatcher.add_to_queue(embedded_file)
```

This will place the file onto the dispatcher to be then picked up by the appropriate Component parser.

By default, anything placed onto the queue will automatically be output by the MWCP reporter. *(You can disable this by setting `output_file=False` keyword argument when initializing the `FileObject`)*
Therefore, even if you don't have a parser that can pick this up, but would like to output it, it's still a good idea to put it on the queue instead of outputting the file manually. This will allow the possibility of a future Component parser being made that can handle the file.


```python
    def run(self):
        """
        Extract metadata and implant from Foo Dropper.
        """
        # Decrypt and report implant.
        key = self._extract_rc4_key(self.file_object.file_data)
        if key:
            # Report key.
            self.reporter.add_metadata('key', key.encode('hex'))
            self.reporter.add_metadata('other', {'rc4_key': key.encode('hex'))

            # Decrypt and dispatch implant.
            implant_data = self._decrypt_implant(key, self.file_object.file_data)
            if implant_data:
                implant_file_object = FileObject(implant_data, reporter=self.reporter)
                self.dispatcher.add_to_queue(implant_file_object)
```

## Raising UnableToParse error
The `mwcp.UnableToParse` exception can be thrown if a component parser that has been correctly identified has failed to parse the file and you would like other parsers to be tried.
This can be useful if identification would require heavy computation that you do not want to run twice.

```python
from mwcp import ComponentParser, UnableToParse

class FooTrojan(ComponentParser):
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

        self.reporter.add_metadata("c2_address", config.c2_address)
```


## Shared information across parsers.
If you would like to share information that can be used by another parser. (eg. encryption keys)
You can store this information in the `knowledge_base` contained in the dispatcher object.
Since all parsers will have access to the dispatcher, a parser can pull data stored in here from another parser.

However, the receiving parser should not assume that the other parser ran and should handle the situation
where it cannot get the information.

*NOTE: If you are trying to decrypt an embedded file. It's better to perform the decryption within
the first parser that contains the embedded file and then dispatch the decrypted file. You should not dispatch the encrypted file and pass the key through the knowledge base if you can prevent it.*

```python
# First component parser
def run(self):
    # ...
    self.dispatcher.knowledge_base['rc4_key'] = rc4_key
    # ...

# Second component parser
def run(self):
    # ...
    rc4_key = self.dispatcher.knowledge_base.get('rc4_key', None)
    if not rc4_key:
        self.reporter.debug('Unable to retrieve rc4 key.')
        return
    # ..
```

## Example Parser

```python
import os

from mwcp import Parser, ComponentParser, FileObject, Dispatcher


class FooTrojan(ComponentParser):
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
        return file_object.pe and cls.MAGIC in file_object.file_data

    def run(self):
        """
        Extract metdata from Foo Trojan.
        """
        ip_address = self._extract_ip_address()
        self.reporter.add_metadata("c2_address", ip_address)


class FooDropper(ComponentParser):
    """Parser for the Foo Trojan."""
    DESCRIPTION = 'Foo Dropper'

    IMPLANT_INDICATOR = b'ISTOREDMYIMPLANTHERE:'

    @classmethod
    def identify(cls, file_object):
        """
        Identify a Foo Dropper.

        :param file_object: dispatcher.FileObject object

        :return: Boolean value indicating if file is a Foo Trojan.
        """
        return file_object.pe and file_object.pe.is_dll() and self.file_object.file_name.endswith('FooD.dll')

    def run(self):
        """
        Extract metadata and implant from Foo Dropper.
        """
        # Decrypt and report implant.
        key = self._extract_rc4_key(self.file_object.file_data)
        if key:
            # Report key.
            self.reporter.add_metadata('key', key.encode('hex'))
            self.reporter.add_metadata('other', {'rc4_key': key.encode('hex'))

            # Decrypt and dispatch implant.
            implant_data = self._decrypt_implant(key, self.file_object.file_data)
            if implant_data:
                implant_file_object = FileObject(implant_data, reporter=self.reporter)
                self.dispatcher.add_to_queue(implant_file_object)


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

*Another example can be found in [bar_malwareconfigparser.py](mwcp/parsers/bar_malwareconfigparser.py).*
