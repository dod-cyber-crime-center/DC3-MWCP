# Parser Installation

To make a parser available for use, place it in a directory with the name `<name>.py` Where `<name>` is a unique name you provide. Usually the name of the malware family.
Then pass the directory containing your parsers to the DC3-MWCP tool being used.
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

*DC3-MWCP will ignore any files starting with `_` in the parser directory.*


## Formal Parser Packaging
If you would like to package your parsers in a more formal and shareable way,
DC3-MWCP supports the use of setuptool's entry_points to register parsers from within
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
|   |- parsertests/  # Tests should be found as a top level directory within your package.
|   |   |- baz.json
|   |   |- foo.json
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
    include_package_data=True,
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

*(More information about setuptools can be found here: [https://setuptools.readthedocs.io]())*

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


## Parser Contribution
We will be happy to accept any new contributions to DC3-MWCP, including new and updated parsers.

If you would like to contribute a parser to DC3-MWCP's default parser set, please do the following:
1. Fork our repo into your own github account.
1. [Install](../README.md#install) in development mode using your forked repo.
1. Add your parser and parser tests to the "mwcp/parsers" and "mwcp/parsertests" directories respectively.
    - Please read the [Parser Development Guide](ParserDevelopmentGuide.md) and [Testing Guide](Testing.md) for help
    creating your parser.
1. Update the "mwcp.parsers" entry point in `setup.py` to add your new parser.
    ```python
    'mwcp.parsers': [
        # ...
        'MyParser = mwcp.parsers.my_parser:MyParser'
    ]
    ```
1. If your parser requires a new python dependency, you may define the dependency in the `install_requires` list in the same `setup.py` file.
1. Add a short description of your contribution to the "Unreleased" section of the [CHANGELOG.md](../CHANGELOG.md) file. (You may need to create the section if this is the first contribution since the last release.)
    - Make sure you give yourself credit!
1. Commit all changes into a few meaningful commit messages. (Rebase to remove "fixup" commits if necessary)
1. Submit a pull request.
