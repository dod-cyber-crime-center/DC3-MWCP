# Parser Components

Parsers are created by inheriting from the `mwcp.Parser` class. An instance of this class comes with 4 major
components to assist in parsing a file:

- [FileObject](#fileobject) - The file currently being parsed.
- [Report](#report) - Used to report on parsed configuration data.
- [Dispatcher](#dispatcher) - Used to add new embedded files to the processing queue.
- [Logger](#logger) - Used to log debugging, informational, and error messages.
- [Tagging](#tagging) - Used to provide contextual tags to elements.
- [Knowledge Base](#knowledge-base)

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

- `data` - The raw data of the file.
- `name` - Name of the file (or an auto-generated stub)
- `description` - Description of the file.
  - This gets auto-set by the identifying parser's `DESCRIPTION` attribute, but can be overwritten as desired.
- `tags` - User defined set of keyword tags for the file.
  - These get set by using `.add_tag()` and/or automatically by the parser's `TAGS` attribute.
- `file_path` - The actual file path as found in the file system (if backed by a real file).
  - (This is primarily used for the initial input file.)
- `md5`, `sha1`, `sha256` - Hashes of the given file.
- `pe` - A `PEFile` object of the file or `None` if file is not a PE.
- `resources` - List of PE resources (if a PE)
- `elf` - An `ELFFile` object of the file or None if the file is not an ELF.
- `parser_history` - A history of all the parser classes that have processed this file.
- `knowledge_base` - A dictionary of miscellaneous information usually set by parsers to exchange information.
- `parent` - The `mwcp.FileObject` object that this file was extracted from or None if this is the original input file.
- `children` - The `mwcp.FileObject` objects that have been generated or dispatched by this file.
- `siblings` - The `mwcp.FileObject` objects that share the same parent of this file.
- `ancestors` - The `mwcp.FileObject` objects for the full parental hierarchy.
- `descendants` - The `mwcp.FileObject` objects that came from the current file.

A file-like object can be generated in a context manager using `.open()`.
This can be helpful if a file stream is needed.

```python
with self.file_object.open() as fo:
    fo.read(10)
```

A temporary file path can be generated in a context manager using `.temp_path()`.
This can be helpful for external utilities that require a real file path.

This directory will not be deleted after processing if the environment variable `MWCP_KEEP_TMP`
is set to `true` or `1`.
The last temporary directory created will be symbolically linked to `mwcp_current`. (In Windows, "Developer Mode" must be enabled.) 

```python
with self.file_object.temp_path() as file_path:
    _some_library_that_needs_a_path(file_path)
```

## Report

You can report configuration data into `self.report`, which is an instance of a `mwcp.Report` class.

You can add metadata via the `add()` function, which takes a metadata element defined in `mwcp.metadata`.

Malware specific metadata that does not fit one of the defined metadata elements can be added using the `Other` element, passing in a key/value pair for this custom metadata item.
Remember that the metadata elements are designed to encompass data in a standardized format, not necessarily to match exactly how data is encoded in the malware being analyzed. The `Other` element is designed to capture specimen and family specific nuances.

```python
from mwcp import metadata

...

# Report key.
key = self._extract_rc4_key(self.file_object.data)
if key:
    self.report.add(metadata.EncryptionKey(key=key, algorithm="rc4"))

# Report mutex.
mutex = self._extract_mutex(self.file_object.data)
if mutex:
    self.report.add(metadata.Mutex(mutex))

# Report non-standard element.
config_display_name = self._extract_config_display_name(self.file_object.data)
if config_display_name:
    self.report.add(metadata.Other("config_display_name", config_display_name))
```

## Dispatcher

You can access the underlying `mwcp.Dispatcher` object used to control the parsers from `self.dispatcher`.

The Dispatcher works by running a queue of input files on a specific list of parsers. Each parser identifies if it can parse the given file. If it identifies the file, the dispatcher
will initialize and run the parser. The parser can then report any metadata as well as extract and place any
embedded files onto the queue for further processing.

To dispatch newly found files, create a `mwcp.FileObject` object and then pass it to the dispatcher
using the `add()` function.

```python
from mwcp import FileObject


# ...

def run(self):
    """
    Extract metadata and implant from Foo Dropper.
    """
    # Decrypt and report implant.
    key = self._extract_rc4_key(self.file_object.data)
    if key:
        # Decrypt and dispatch implant.
        implant_data = self._decrypt_implant(key, self.file_object.data)
        if implant_data:
            implant_file_object = FileObject(implant_data, description='Decrypted Implant')
            self.dispatcher.add(implant_file_object)
```

*NOTE: Setting the description for the extracted file is not usually necessary since it will automatically
be set with the description of the parser that identifies the file.*

## Logger

The `self.logger` object is a logger object from the `logging` library.
Using this logger will ensure the component's name is added to the log message.

It is a good idea to use logging to help inform the user on the progress of the parser and if the parser may
need to be updated due to a new variant of the sample.

```python
    def run(self):
        """
        Extract metadata and implant from Foo Dropper.
        """
        # Decrypt and report implant.
        key = self._extract_rc4_key(self.file_object.data)
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

## Tagging

Tags can be added to any produced metadata element, file object, or the report itself.
To add a tag, simply call `add_tag()` with a provided sequence of tags.
These tags provide an easy way to add context to the results based on your own
defined standard such as actor set, technique, artifact location, etc.

The `add_tag()` function will return the instance of the element it is
being added to, allowing for easy addition of tags within existing code.

```python
from mwcp import metadata

# Report key and provide context that is was use for the implant.
key = self._extract_rc4_key(self.file_object.data)
if key:
    self.report.add(metadata.EncryptionKey(key=key, algorithm="rc4").add_tag("implant"))

# Add embedded implant and add tag that it came from overlay.
self.dispatcher.add(FileObject(implant_data).add_tag("overlay"))

# Add a global tag to the report itself.
self.report.add_tag("acme_triage", "ransomware")


# Attach a tag for known actor set after positive identification.
@classmethod
def identify(cls, file_object):
    if "MAGIC" in file_object.data:
        file_object.add_tag("SuperActor")
        return True
    return False
```

Tags can also be included as an attribute on a `Parser` class to automatically attach on all identified files.

```python
from mwcp import Parser


class Implant(Parser):
    DESCRIPTION = "SuperMalware Implant"
    TAGS = ("implant", "SuperMalware")

    ...
```

## Knowledge Base

If you would like to share information that can be used by another parser. (eg. encryption keys)
You can store this information in the `knowledge_base` contained in the [Report](#report) object.
Since all parsers will have access to the report, a parser can pull data stored in here from another parser.

However, the receiving parser should not assume that the other parser ran and should handle the situation
where it cannot get the information.

*NOTE: If you are trying to decrypt an embedded file. It's better to perform the decryption within
the first parser that contains the embedded file and then dispatch the decrypted file. 
You should not dispatch the encrypted file and pass the key through the knowledge base if you can prevent it.*

```python
# First parser
def run(self):
    # ...
    self.report.knowledge_base['rc4_key'] = b"\xde\xad\xbe\xef"
    # ...

# Second parser
def run(self):
    # ...
    rc4_key = self.report.knowledge_base.get('rc4_key', None)
    if not rc4_key:
        self.logger.warning('Unable to retrieve rc4 key.')
        return
    # ..
```

*NOTE: The `knowledge_base` can also be directly accessed from the parser using `self.knowledge_base`*

There is also a separate `knowledge_base` for each [FileObject](#fileobject) object, which can be used for storing specific information for that file, which other parsers can access by traversing the parental hierarchy.

```python
# First parser
def run(self):
    # ...
    self.file_object.knowledge_base['rc4_key'] = b"\xde\xad\xbe\xef"
    # ...


# Second parser
def run(self):
    # ... 
    if parent := self.file_object.parent:
        if rc4_key := parent.knowledge_base.get('rc4_key', None):
            self.logger.warning("Obtained parent's RC4 key.")
```

### External Knowledge

The `knowledge_base` can be prepopulated with additional knowledge provided by the user through the following methods:

- `--param` flag on the [CLI](../README.md#cli-tool).
- `param` [REST](../README.md#arguments) request argument.
- `knowledge_base` [keyword argument](../README.md#python-api) on `mwcp.run()`

This can be used to provide information externally obtained by another source before parsing starts.

A parser can also obtain this information explicitly through `Report.external_knowledge`.
