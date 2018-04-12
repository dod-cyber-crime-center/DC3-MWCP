# Parser Installation

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
NAME                      SOURCE                     AUTHOR          DESCRIPTION
-------------------------------------------------------------------------------------------------------------------
bar                       mwcp                       DC3             exmaple parser using the Dispatcher model
baz                       C:\my_parsers              ACME            my baz parser
foo                       C:\my_parsers              ACME            my foo parser
foo                       mwcp                       DC3             example parser that works on any file
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
# in setup.py

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
NAME                      SOURCE                     AUTHOR          DESCRIPTION
-------------------------------------------------------------------------------------------------------------------
bar                       mwcp                       DC3             exmaple parser using the Dispatcher model
baz                       mwcp-acme                  ACME            example parser made by ACME
baz                       mwcp-intech                INTEC           example parser made by INTECH
foo                       mwcp                       DC3             example parser that works on any file
foo                       mwcp-acme                  ACME            example parser made by ACME
```

NOTE: If multiple mwcp packages contain parsers with the same name (case-sensitive), then all parsers with that name will be run back-to-back. (With results merged together.)
```
mwcp-tool -p baz   # Will run the "baz" parser from both mwcp-acme and mwcp-intech
```

To specify a particular parser, you can provide the source name (name in the "()") using ":" notation.
```
mwcp-tool -p mwcp-acme:baz   # Will run the "baz" parser from mwcp-acme only.
```

