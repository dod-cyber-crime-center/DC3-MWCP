# Parser Development

The high level steps for parser development are:

- Create new *_malwareconfigparser module
- Subclass `mwcp.Parser`
- Implement run()
- Use reporter object
  - Access malware sample
  - Report metadata
  - etc.

`foo_malwareconfigparser.py` is provided as an example and may be used as a template:


```python
import os
from mwcp import Parser

class Foo(Parser):
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

## Dispatching Component parsers
The above example works for simple cases. However, when you run into malware containing multiple components
embedded within each other with multiple variations, it can easily grow your parser to an unmanageble size.

MWCP comes with a Dispatcher model that allows you to organize your code based on their individual components
and variations.

For documentation please read: [Dispatcher Parser Development](DispatcherParserDevelopment.md).


## Parser Installation
To make a parser available for use, place it in a directory with the name `<name>.py` Where `<name>` is a unique name you provide. Usually the name of the malware family.
Then pass the directory containing your parsers to the mwcp tool being used.
```
mwcp-tool --parserdir=C:\my_parsers -p <name> <input_file>
# OR
mwcp-server --parserdir=C:\my_parsers
```

You should then find your parser available alongside the default parsers that come with MWCP.
```
mwcp-tool --parserdir=C:\my_parsers -l
```

```
bar (mwcp)                                  DC3      exmaple parser using the Dispatcher model
baz (c:\my_parsers)                         DC3      my baz parser
foo (c:\my_parsers)                         DC3      my foo parser
foo (mwcp)                                  DC3      example parser that works on any file
```

## Formal Parser Packaging
If you would like to package your parsers in a more formal and shareable way,
MWCP supports the use of setuptool's entry_points to register parsers from within
your own python package.

This allows for a number of benefits:
- Provides a way to encapsulate your parsers as a proper python package.
- Gives users an easy way to install MWCP and your parsers at the same time. (pip installable)
- Allows you to specify what versions of MWCP your parsers support.
- Allows you to easily specify and install extra dependencies your parsers require.
- Allows you to maintain versions of your parsers.
- Provides a way to distribute and maintain extra helper/utility modules that are used by your parsers.

To set this up, structure your parsers into a package and include a `setup.py` file to declare it as a python package. It should look something like this:
```
some_root_dir/
|- README.md
|- setup.py
|- mwcp_acme/
|   |- __init__.py
|   |- parsers/
|   |   |- __init__.py
|   |   |- baz.py     # filenames do not need to end in _malwareconfigparser when doing it this way.
|   |   |- foo.py
```

Then, within your `setup.py` file, declare your parsers as entry_points to "mwcp.parsers" pointing
to your mwcp.Parser classes. (NOTE: The name set before the "=" will be the name of the parser when using the tool.)
```python
from setuptools import setup, find_packages


setup(
    name='mwcp-acme',
    description='DC3-MWCP parsers developed by ACME inc.',
    version='1.0.0',
    packages=find_packages(),
    entry_points={
        'mwcp.parsers': [
            'baz = mwcp_acme.parsers.baz:BazParser',
            'foo = mwcp_acme.parsers.foo:FooParser',
        ]
    },
    install_requires=[
        'mwcp>=1.1.0',
        # Add any other requirements needed for this group of parsers here.
    ]
)
```

*(More information about setuptools can be found here: [setuptools.readthedocs.io/en/latest/setuptools.html]())*

Then, install your package.
```
cd some_root_dir
pip install .
```

Your parsers should now be available alongside the default parsers MWCP and any other mwcp packages.
```
mwcp-tool -l
```
```
bar (mwcp)                                                             DC3      exmaple parser using the Dispatcher model
baz (mwcp-acme)                                                        ACME     example parser made by ACME
baz (mwcp-intech)                                                      INTEC     example parser made by INTECH
foo (mwcp)
foo (mwcp-acme)                                                        ACME      example parser made by ACME
```

NOTE: If multiple mwcp packages contain parsers with the same name (case-sensitive), then all parsers with that name will be run back-to-back. (With results merged together.)
```
mwcp-tool -p baz   # Will run the "baz" parser from both mwcp-acme and mwcp-intech
```

To specify a particular parser, you can provide the source name (name in the "()") using ":" notation.
```
mwcp-tool -p mwcp-acme:baz   # Will run the "baz" parser from mwcp-acme only.
```



## Parser Development Tips
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
- Use [mwcp.utils.construct](construct.ipynb) to help organize your config structures.

## Tech Anarchy Bridge

While DC3-MWCP does not include any malware parsers, it does include a bridge to enable use
of the parsers provided by Kev of techanarchy.net/malwareconfig.com. The purpose
of this bridge is to execute the Tech Anarchy parsers, capture the output, and normalize
the fields. This bridge can be used to create simple DC3-MWCP modules which call the underlying
Tech Anarchy parsers. It is the responsibility of the user to ensure that field mappings are
correct, adjusting the bridge as necessary.

See mwcp/resources/techanarchy_bridge.py