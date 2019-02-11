# Parser Components

Parsers are created by inheriting from the `mwcp.Parser` class. An instance of this class comes with 4 major
components to assist in parsing a file:

- [self.file_object](#fileobject) - The file currently being parsed.
- [self.reporter](#reporter) - Used to report on parsed configuration data.
- [self.dispatcher](#dispatcher) - Used to add new embedded files to the processing queue.
- [self.logger](#logger) - Used to log debugging, informational, and error messages.


### Guides
- [Parser Development](ParserDevelopment.md)
- [Parser Components](ParserComponents.md)
- [Parser Installation](ParserInstallation.md)
- [Parser Testing](ParserTesting.md)
- [Python Style Guide](PythonStyleGuide.md)

## FileObject
The file being processed by a parser is accessible via `self.file_object`, which is an instance of the 
`mwcp.FileObject` class. This class contains a variety of useful attributes describing the file.

It contains the following attributes:
- `file_data` - The raw data of the file.
- `file_name` - Name of the file (or a auto generated stub)
- `file_path` - A full path to the file which can be used for external utilities that require it.
- `md5`, `sha1`, `sha256` - Hashes of the given file.
- `pe` - A `PEFile` object of the file or `None` if file is not a PE.
- `resources` - List of PE resources (if a PE)
- `elf` - An `ELFFile` object of the file or None if the file is not an ELF.
- `parser_history` - A history of all the parser classes that have processed this file.
- `parent` - The `mwcp.FileObject` object that this file was extracted from or None if this is the original input file.


You can also access a file-like object (a `io.BytesIO` object) if you wrap the object using a `with` statement.

```python
for self.file_object as fo:
    fo.read(10)
```

## Reporter
You can report configuration data using `self.reporter`, which is an instance of a `mwcp.Reporter` class.

You can add metadata via the `add_metadata(key, value)` function
- `key` is the field name of the metadata item. This should be one of the standardized fields reported in [mwcp/resources/fields.json](../mwcp/resources/fields.json). (Hint: Run `mwcp-tool -k` to get a list of all fields.
- `value` is the actual value to report.
   - For a "listofstrings" type, this is simply the string to report.
   - For a "listofstringtuples" type, this is a tuple or list.
   - For a "dictofstrings" type, this is a dictionary with string values.
- Malware specific metadata that does not fit one of the standard fields can be added to the "other" field, passing in a dictionary containing the key:value pair for this custom metadata item.
- All strings provided to the add_metadata function should either be a Unicode string or a UTF-8 encoded byte string. If a string contains characters that cannot be decoded as UTF-8, they will be replaced with the Unicode replacement character (�).

```python
    key = self._extract_rc4_key(self.file_object.file_data)
    if key:
        # Report key.
        hex_key = binascii.hexlify(key)
        self.reporter.add_metadata('key', hex_key)
        self.reporter.add_metadata('other', {'rc4_key': hex_key})
```

### Guidance on standardized fields

When possible, use the most comprehensive field possible. Ex. if you have an address and a tcp port, report the socketaddress instead of the address and port separately

 Subfields are parsed automatically. They can be reported, but it is not necessary. Ex. if you report a socketaddress, reporting the address and port is redundant and not necessary

Remember that the standardized fields are designed to encompass data in a standardized format, not necessarily to match exactly how data is encoded in the malware being analyzed. The "other" fields are designed to capture specimen and family specific nuances.


## Dispatcher
You can access the underlining `mwcp.Dispatcher` object used to control the parsers from `self.dispatcher`.

The Dispatcher works by running a queue of input files on a specific list of parsers. Each parser identifies if it can parse the given file. If it identifies the file, the dispatcher
will initialize and run the parser. The parser can then report any metadata as well as extract and place any
embedded files onto the queue for further processing.

To dispatch newly found files, create a `mwcp.FileObject` object and then pass it to the dispatcher
using the `add_to_queue()` function.

```python
    from mwcp import FileObject

    # ...

    def run(self):
        """
        Extract metadata and implant from Foo Dropper.
        """
        # Decrypt and report implant.
        key = self._extract_rc4_key(self.file_object.file_data)
        if key:
            # Decrypt and dispatch implant.
            implant_data = self._decrypt_implant(key, self.file_object.file_data)
            if implant_data:
                implant_file_object = FileObject(implant_data, reporter=self.reporter, description='Decrypted Implant')
                self.dispatcher.add_to_queue(implant_file_object)
```

*NOTE: Setting the description for the extracted file is not usually necessary since it will automatically
be set with the description of the parser that identifies the file.*


### Sharing information across parsers
If you would like to share information that can be used by another parser. (eg. encryption keys)
You can store this information in the `knowledge_base` contained in the dispatcher object.
Since all parsers will have access to the dispatcher, a parser can pull data stored in here from another parser.

However, the receiving parser should not assume that the other parser ran and should handle the situation
where it cannot get the information.

*NOTE: If you are trying to decrypt an embedded file. It's better to perform the decryption within
the first parser that contains the embedded file and then dispatch the decrypted file. 
You should not dispatch the encrypted file and pass the key through the knowledge base if you can prevent it.*

```python
# First parser
def run(self):
    # ...
    self.dispatcher.knowledge_base['rc4_key'] = rc4_key
    # ...

# Second parser
def run(self):
    # ...
    rc4_key = self.dispatcher.knowledge_base.get('rc4_key', None)
    if not rc4_key:
        self.logger.warning('Unable to retrieve rc4 key.')
        return
    # ..
```




## Logger
The `self.logger` object is a logger object from the `logging` library.
Using this logger will ensure the component's name is added to the log message.

It is a good idea to use logging to help inform the user on the progress of the parser and if the parser may
need to be updated due to new variant of the sample.

```python
    def run(self):
        """
        Extract metadata and implant from Foo Dropper.
        """
        # Decrypt and report implant.
        key = self._extract_rc4_key(self.file_object.file_data)
        if key:
            # Report key.
            self.logger.info('Found the key!')
            # ...
        else:
            self.logger.warning('Unable to find the key! New variant?')
```

If you are logging an external function outside of any Parser class, you can either
pass along the logger object or create a global logger object using `logging.getLogger(__name__)`

```python
import logging

from mwcp import Parser

logger = logging.getLogger(__name__)


def some_module_level_function():
    logger.info('Doing this thing.')
    return True


class BarImplant(Parser):
    # ...

```


Please see the [README](../README.md#logging) for more information.