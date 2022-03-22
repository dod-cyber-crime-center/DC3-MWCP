# Parser Installation Guide

- [Adding a Directory](#adding-a-directory)
- [Grouping Parsers](#grouping-parsers)
- [Formal Parser Packaging](#format-parser-packaging)
- [Parser Contribution](#parser-contribution)


### Guides
- [Parser Development](ParserDevelopment.md)
- [Parser Components](ParserComponents.md)
- [Parser Installation](ParserInstallation.md)
- [Parser Testing](ParserTesting.md)
- [Python Style Guide](PythonStyleGuide.md)


## Adding a Directory
To install your own custom parser, please follow these steps:

1. Place all your parsers into a directory. If you would like to use sub directories
make sure to include `__init__.py` files so Python can see them as packages.
*(Files starting with `_` will be ignored.)*

1. Then pass the directory containing your parsers to the DC3-MWCP tool being used.

```console
> mwcp --parser-dir=C:\my_parsers parse <name> <input_file>
# OR
> mwcp --parser-dir=C:\my_parsers serve
```

You should then find your parsers available alongside the default parsers that come with MWCP using
the `mwcp list` command.

```console
> mwcp --parser-dir=C:\my_parsers list --all
NAME            SOURCE         AUTHOR    DESCRIPTION
--------------  -------------  --------  -------------------------------------
bar             mwcp           DC3       Example parser
foo             mwcp           DC3       Example parser that works on any file
Foo.Implant     c:\my_parsers            Foo Implant
Foo.Downloader  c:\my_parsers            Foo Downloader
```

If you don't include the `--all` flag, you will notice that your parsers are not listed.
This is because, by default, DC3-MWCP will only list parser groups defined in a parser configuration file.
To create a parser group, please see the next section.

For more persistence, you can add the directory path to the configuration parameter `PARSER_DIR`.
(Run `mwcp config`). This will cause `--parser-dir` to automatically apply if not supplied. 


## Grouping Parsers
DC3-MWCP has the ability to chain multiple parsers together into a group to create a larger
parser. This was originally referred to as the "Dispatcher model".
A parser group consists of a name, description, author, and list of parsers (or other parser groups) to run (in that order).

Creating a group allows you to chain
the processing of possible components the parsers could extract.
For example, if you have a malware family that comprises of a downloader, loader, implant, and could
possibly be UPX packed.

Parser groups are defined using a YAML configuration file with the following structure:

```yaml
GroupName:
    description: Description of parser group
    author: ACME
    parsers:  # List of parsers/parser groups to run (in order)
        - Foo.Downloader
        - Foo.Implant
```

This YAML file must be declared as the `config` attribute in the root `__init__.py` of your parser package.

```python
# file: mwcp-acme/parsers/__init__.py

import os


config = os.path.join(os.path.dirname(__file__), "parser_config.yml")
```


You may omit the top level name if it matches the name of the group:

```yaml
Foo:
    description: A Foo parser
    author: ACME
    parsers:
        - .Downloader  # equivalent to "Foo.Downloader"
        - .Implant
```

You may also reference other parser groups as a parser.

```yaml

Decoy:
    description: Decoy Files
    author: ACME
    parsers:
        - .DOC
        - .DOCX
        - .PDF
        - .RTF
        - .JPG

Foo:
    description: A Foo parser
    author: ACME
    parsers:
        - Decoy
        - .Downloader
        - .Implant
```


You may also reference parser components/groups from external sources using `:` notation.

```yaml
Foo:
    description: A Foo parser
    author: ACME
    parsers:
      - LlamaCorp:Decoy        # Imports LlamaCorp's Decoy parser group.
      - LlamaCorp:Foo.Carrier  # Imports LlamaCorp's Foo.Carrier parser component.
      - .Downloader
      - .Implant
```

You may also create direct aliases to other parser groups by providing just the parser name.

```yaml
Foo:
    description: A Foo parser
    author: ACME
    parsers:
        - .Downloader
        - .Implant

FooAlias: Foo
```


### Parser Group Options
A number of options can be toggled on or off when defining a parser group.
To set, simply add the option along with the author and description.
If an option is not provided, it will be set to its default which is defined below.

```yaml
Decoy:
    description: Decoy File
    author: ACME
    greedy: true
    overwrite_descriptions: true  
    embedded: true
    ...
    parsers:
      ...
```

- `greedy` (default: `false`) -  By default, only the first identified parser in the list is run on the file.
    If set to `true` all parsers that have identified the file is run. 
    The description of the last parser to identify the file is used for reporting.
    *(Useful if parser components are organized by file characteristics like decryption algorithms.)*
- `output_unidentified` (default: `true`) - By default, if a file does not get identified by a parser, 
    the file is still written out to the file system. 
    If set to `false`, only identified files is written out.
    *(Useful if the group contains a parser that could dispatch a lot of uninteresting files like PE resources.)*
- `overwrite_descriptions` (default: `false`) - By default, if the developer of a parser sets the `description` 
    argument on a dispatched `FileObject`, that description replaces the description of any identified parser
    and is used for reporting.
    If set to `true`, the description of an identified parser is used instead. 
    Therefore, the description set by the developer is only used if the file is not identified by any parsers.
- `embedded` (default: `false`) - If a parser group is referenced as a parser for another group, any dispatched files 
    are processed against the local list of parsers first before being passed upstream to the parent group.
    If set to `true`, all dispatched files are passed up the the parent immediately. 
    That is, setting this to `true` is the equivalent of embedding the listed parsers directly into the parent's parser list
    that reference the group.
    *(Useful if the group contains a lot of generic parsers like decoy documents that you want to have lower priority)*


## Formal Parser Packaging
If you would like to package your parsers in a more formal and shareable way,
DC3-MWCP supports the use of setuptool's entry_points to register parsers from within
your own python package.

This allows for a number of benefits:
- Provides a way to encapsulate your parsers as a proper python project.
- Gives users an easy way to install MWCP and your parsers at the same time. (pip installable)
- Allows you to specify what versions of MWCP your parsers support.
- Allows you to easily specify and install extra dependencies your parsers require.
- Allows you to maintain versions of your parsers.
- Provides a way to distribute and maintain extra helper/utility modules that are used by your parsers.

To set this up, structure your parsers into a package and include a `setup.py` file to declare it as a python project.

It should look something like this:
```
some_root_dir/
|- README.md
|- setup.py
|- mwcp_acme/
|   |- __init__.py
|   |- parsers/
|   |   |- __init__.py
|   |   |- parser_config.yml
|   |   |- baz.py
|   |   |- foo.py
|   |   |- tests/  # Tests should be found within the root of your parsers package with the name "tests"
|   |   |   |- baz.json
|   |   |   |- foo.json
```

If you have a parser configuration file (`parser_config.yml`). Make sure you include
the path to the file as the variable `config` in the `__init__.py` in the root parsers folder.


Then, within your `setup.py` file, declare an entry_point for "mwcp.parsers" pointing
to the package containing your parsers. The name set before the "=" will be the source name for
the parsers contained within. *(Your project may create multiple entry points provided they
have unique source names)*

```python
# in setup.py

from setuptools import setup, find_packages


setup(
    name='mwcp_acme',
    description='DC3-MWCP parsers developed by ACME inc.',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        'mwcp.parsers': [
            'ACME = mwcp_acme.parsers',
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
```console
> cd some_root_dir
> pip install .
```

Your parsers should now be available alongside the default parsers MWCP and any other mwcp packages.
```console
> mwcp list
NAME            SOURCE         AUTHOR    DESCRIPTION
--------------  -------------  --------  -------------------------------------
bar             mwcp           DC3       Example parser
foo             mwcp           DC3       Example parser that works on any file
foo             ACME           ACME      Example parser made by ACME
baz             ACME           ACME      Example parser made by ACME
```


NOTE: If multiple mwcp projects contain parsers with the same name (case-sensitive), then all parsers with that name will be run back-to-back. (With results merged together.)
```console
> mwcp parse foo <input>   # Will run the "foo" parser group from both mwcp and ACME.
```

To specify a particular parser, you can provide the source name using ":" notation.
```console
> mwcp parse ACME:foo <input>  # Will run the "foo" parser from ACME only.
```


### Setting parser source
If you would like to use the MWCP tools solely with your parsers only, you can provide
the `--parser-source` flag to limit parsers to a single source.

```console
> mwcp --parser-source ACME list
> mwcp --parser-source ACME parse foo <input>
```

For more persistence, you can add the name of your parser source to the configuration parameter `PARSER_SOURCE`.
(Run `mwcp config`). This will cause `--parser-source` to automatically apply if not supplied. 



## Parser Contribution
We will be happy to accept any new contributions to DC3-MWCP, including new and updated parsers.

If you would like to contribute a parser to DC3-MWCP's default parser set, please do the following:
1. Fork our repo into your own github account.
1. [Install](../README.md#install) in development mode using your forked repo.
1. Add your parser and parser tests to the "mwcp/parsers" and "mwcp/parsers/tests" directories respectively.
    - Please read the [Parser Development Guide](ParserDevelopmentGuide.md) and [Testing Guide](Testing.md) for help
    creating your parser.
1. If your parser requires a new python dependency, you may define the dependency in the `install_requires` list in the same `setup.py` file.
1. Add a short description of your contribution to the "Unreleased" section of the [CHANGELOG.md](../CHANGELOG.md) file. (You may need to create the section if this is the first contribution since the last release.)
    - Make sure you give yourself credit!
1. Commit all changes into a few meaningful commit messages. (Rebase to remove "fixup" commits if necessary)
1. Submit a pull request.
