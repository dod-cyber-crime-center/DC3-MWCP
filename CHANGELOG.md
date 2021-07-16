# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Added `mode` attribute for EncryptionKey to report on block cipher mode.
  - Updated testing utility to ensure test cases older than 3.3.2 ignore this new property.

### Changed
- Added word wrap for long fields in a generated report.
- Switched "html" report output format to be consistent with "simple" and "markdown" formats.
- Improved display formatting for EncryptionKey, RSAPrivateKey, and RSAPublicKey.

### Fixed
- Fixed test case path for `foo` parser, changed to a path which will always exist since input file is irrelevant. (@ddash-ct)
- Fixed issue with results in the new metadata style not being dedupped across file sources.
- Split report results are now correctly ordered by processing order.
- Fixed issue with running `mwcp test -u` command to update all legacy parser tests.

### Removed
- Removed unused `split` argument in `Report` initialization.


## [3.3.1] - 2021-06-28

### Added
- Added support for providing a custom logging filter when running a parser.

### Changed
- Updated `poshdeob` utility to work with the latest version of pyparsing.
  - Removed version pinning for pyparsing dependency.

### Fixed
- Fixed "can't set attribute" error occurring when using web server.


## [3.3.0] - 2021-06-10

*NOTE: This release may require updating setuptools to successfully install.*

### Added
- Added `mwcp.run()` as a shortcut for running a parser and getting back its results. (See [documentation](/README.md#python-api))
- Added ability to provide a `mwcp.Parser` class directly to `mwcp.run()`.
  This is helpful for quick one-off scripting.
- Added `--split` option within the `mwcp parse` command, which changes the report to display
  metadata split by originating file instead of all being consolidating with the initial input file.
  (This option is only available when `--no-legacy` is enabled.)
- The `Report` class now includes the following output options for programmatically rendering results in different formats:
  - `.as_text()` - Renders sectioned tables of results in a simple text format (this is the default format when using the command line).
  - `.as_markdown()` - Renders sectioned tables of results in markdown.
  - `.as_html()` - Renders a flat table of results in html.
  - `.as_csv()` - Renders a flat table of results in csv.
  - `.as_dataframe()` - Produces a flat table of results in a pandas dataframe.
  - `.file_tree()` - Renders an ascii tree representing the hierarchy of residual files.
- Added ability to add tags to metadata elements. (See [documentation](/docs/ParserComponents.md#tagging))
- Added DecodedString metadata element.
- Added `.compile_time` attribute to `FileObject`.
- Added `.architecture` attribute to `FileObject`.
- Added ability to pass results from `Parser.identify()` into the `Parser.run()` function. (See [documentation](/docs/ParserDevelopment.md#passing-identify-results))


### Changed
- MWCP version can now be accessed from `mwcp.__version__`
- Updated metadata mechanism to an objected-oriented approach. (See [documentation](/docs/ParserComponents.md#report))
- `mwcp.Reporter` has been replaced with `mwcp.Runner`. (However, using `mwcp.run()` is now recommended.)
- Updated json and text report output.
  - NOTE: To keep backwards compatibility, the schema for the original json output is provided by default.
  To enable the new schema, you must provide the `--no-legacy` in the command line.
- `FileObject.data` (and `FileObject.file_data`) has been set to a read-only attribute. 
- Updated parser testing to support the new metadata schema. To use, provide the `--no-legacy` flag to
the `mwcp test` command.
  - Created a new command line tool `mwcp_update_legacy_tests` to update your existing test cases to use the new metadata schema. (See [documentation](/docs/ParserTesting.md#updating-legacy-test-cases))
  - New parser test cases now use pytest.
- Updated text report display and added markdown and html formats.
  - Also added file tree display at the end of the report (for some formats).
- Updated csv output.
- Results from `Parser.identify()` are now cached to prevent repeated processing of the same file.


### Deprecated
- `FileObject.file_path` is planned to be changed to only be a non-None value if the `FileObject` 
instance is backed by a real file on the file system.
    - The creation of a temporary file path has been moved to `.temp_path()`.
- Adding metadata is now done using objects found in `mwcp.metadata`. The key/value approach is deprecated
  and support will be removed in a future major release.
- `mwcp.Reporter` object is deprecated in favor of using either `mwcp.Runner` or `mwcp.run()`.
- The `self.reporter` attribute in a parser has been renamed to `self.report` and is now a `mwcp.Report` object.
  - Interface is currently the same as `mwcp.Reporter`, so your code shouldn't break except for in extreme corner cases.
- The `.metadata` attribute in `mwcp.Reporter` (now called `mwcp.Report`) is deprecated in favor of using `.as_dict()`.
    - WARNING: A best attempt was done to keep the results of the `.metadata` attribute the same. However, due to new validation and type coercion mechanisms, you may run into corner cases where the results are slightly different, causing your parser test to fail. 
- The json schema as described in [fields.txt](mwcp/config/fields.txt) is deprecated in favor
of the schema described in [`mwcp.metadata`](mwcp/metadata.py).
- Providing a "reporter" argument to `FileObject.__init__()` is deprecated.
- `FileObject.output()` and `Reporter.output_file()` is deprecated in favor of adding a `mwcp.metadata.ResidualFile` object to `Report.add()`.
- Using `FileObject.file_path` to get a temporary file path is deprecated in favor of using `.temp_path()`, which is now a context manager.
    - (This change is to ensure we have more guaranteed cleanup of temporary files.)
- `Reporter.managed_tempdir` is deprecated. Instead, the developer should properly create and destroy a temporary directory themselves using Python's builtin library. However, it is best to use `FileObject.temp_path()` or reevaluate if there is a way parsing can be accomplished without writing out a file to the file system if possible.
- The `-i` flag is no longer supported. Input file information will now always be provided (with the exception of legacy JSON output).
- Using a `FileObject` instance in a `with` statement directly to get a file stream is now deprecated. Please use `FileObject.open()` instead.
- `FileObject.file_data` is deprecated in favor of `FileObject.data`.
- `FileObject.file_name` is deprecated in favor of `FileObject.name`.


## [3.2.1] - 2020-11-03
- Added source argument to Dispatcher initialization to comply with new method signature

## [3.2.0] - 2020-10-30

### Changed
- Updated `IMAGE_OPTIONAL_HEADER` to support 64-bit and added missing `DllCharacteristics` Flags. (@ddash-ct)
- Updated `IMAGE_FILE_HEADER.SizeOfOptionalHeader` to enable leveraging `sizeof()`. (@ddash-ct)
- Changed log messages for file identification and misidentification to update phrasing for parsing groups vs parsing components. (@ddash-ct)
- Added support for importing external parser components/groups within a parser configuration. (See [documentation](docs/ParserInstallation.md#grouping-parsers))
- Added support for providing run configuration options to `FileObject.run_kordesii_decoder()` which will be passed 
    along to `kordesii.run_ida()` when calling IDA. (This allows you to provide the new `is_64bit` option if necessary.)

### Fixed
- Fixed glob pattern in Techanarchy wrapper. (@cccs-aa)
- Fixed misspelling of "Characteristics" in `IMAGE_IMPORT_DESCRIPTOR`. (@ddash-ct)
- Fixed infinite loop that can be caused due to a sub-parser throwing an `UnableToParse` exception. (@ddash-ct)
- Fixed bug in construct.Base64 adapter for build with unicode encoding types. (@ddash-ct)
- General fixes to improve support when running under Linux.
    - Changed log configuration usage of `%LOCALAPPDATA%` for the log directory reported by `appdirs`.
- Fixed build issue in `pecon` and added option for setting architecture to 64 bit.

## [3.1.0] - 2020-06-05

### Added
- Added `children` and `siblings` attributes to `FileObject` class.
- Added `--prefix/--no-prefix` command line flag allowing the removal of the first 5
    characters of the md5 prefixed on output files.
    - WARNING: If disabled, unique files with the same file name will be overwritten.
    

### Removed
- Removed deprecated `requirements.txt` file.


## [3.0.1] - 2020-05-01

### Changed
- Setup fixes for PyPi deployment
- Remove deprecated `decoderdir` variable from `file_object.run_kordesii_decoder()` and add `kordesii.register_entry_points()`


## [3.0.0] - 2020-02-20

### Changed
- Dropped support for Python 2

### Removed
- Removed previously deprecated components:
    - Support for reading configuration from enviromnent variables:
        - `MWCP_PARSER_DIR`, `MWCP_PARSER_CONFIG`, `MWCP_PARSER_SOURCE`, `MWCP_TESTCASE_DIR`, `MWCP_MALWARE_REPO`
    - `report_tempfile()` in `Reporter` class
    - `mwcp-tool`, `mwcp-client`, `mwcp-server`, and `mwcp-test` command line tools
    

## [2.2.0] - 2020-01-15

**NOTE: This is the last version to support Python 2. 
The next release will only support Python 3.**

### Added
- Added `--force` flag to `Tester` for adding or updating testcases to ignore errors if set. (@ddash-ct)
- Added `embedded` option that can be set in the parser configuration. (See [documentation](docs/ParserInstallation.md#parser-group-options))

### Fixed
- `pefileutils.obtain_export_list` would contain a `null` entry as the last item in the list for any file
- Errors that occur while importing a parser are no longer silenced.
- Recursive loops in the parser configuration are now detected and cause an error.


## [2.1.0] - 2019-09-10

### Added
- Simple HTML interface with mwcp server. 

### Changed
- The `outputfiles` attribute in `mwcp.Reporter` has been removed. 
Instead, the output file path will be returned by `output_file()`.
- All output filenames now include the first 5 digits of its MD5 and are
converted to file system safe names.
- Configuration is now set using a yaml file located within the user's profile directory.
    - This file can be modified by running `mwcp config`.
- Input file paths in test cases now support environment variable expansion. 
- Input file paths in test cases can include `{MALWARE_REPO}` which will be replaced
by the currently set malware repository path.
- Using `mwcp test Foo --add=...` to a add file that already exists in the test cases will no
longer cause the test case to be updated. This must be explicitly allowed by also adding the `--update` flag.
- Added `mwcp serve` command to run mwcp server.
- mwcp server is now implemented with Flask instead of Bottle.
    - If using the server as a WSGI app, the app instance must be created with
      the factory function `mwcp.tools.server.create_app()`.

### Deprecated
- Setting configuration using environment variables is deprecated. Please use the configuration file instead.

### Removed
- Removed support for adding a prefix to output files.


## [2.0.3] - 2019-06-20

### Fixed
- Updated pefileutils to support pefile version 2018.4.18
- Pinned pyparsing dependency to 2.3.0 to avoid breaking poshdeob.


## [2.0.2] - 2019-04-10
### Changed
- Moved output files to a folder named '{input filename}_mwcp_output' when running `mwcp parse`
  - This prevents output files from being overwritten when running multiple input files.

### Fixed
- Pinned kordesii dependency to 1.4.0 or greater.
- Fixed bug with using old "enableidalog" parameter when running kordesii parsers.
- Fixed tuple error when attempting to use the `--add-filelist` option in `mwcp test`.

### Deprecated
- `Reporter.report_tempfile()` is deprecated. Use `FileObject.output()` instead.


## [2.0.1] - 2019-03-15
### Added
- Added caching of kordesii results.

### Changed
- `mwcp test` can now accept more than one parser.

### Fixed
- Fixed up dispatcher logic to properly work with sub parser groups.
- Fixed missing dispatcher issue when running a single parser directly from command line.
- Fixed up unicode string handling in Reporter.
- Fixed handling of optional capture groups for `Regex` construct helper.


## [2.0.0] - 2019-02-11
### Added
- `sha1` and `sha256` attributes in FileObject class.
- Created a new command line tool called `mwcp` which encompasses parsing and testing in one tool.
    - This tool simplifies and cleans up the old CLI flags and uses subcommands for better organization.
- `--parser-config` flag to specify location of a parser configuration file for a custom parser directory.
- Ability to set a parser source with `--parser-source` flag.
- Streamlined the wrapper for [TechAnarchy](http://techanarchy.net/2014/04/rat-decoders/) parsers.
    - Parsers can be run using the naming scheme `TA.{decoder_filename}` after placing the parsers 
      in the `mwcp/resources/RATDecoders` directory.
- `pecon` PE file reconstruction utility.
- `poshdeob` Powershell deobfuscator utility.
- Support for relative input paths in test cases.

### Changed
- Parsers are now declared using a YAML configuration file.
    - Please see the [Parser Installation](docs/ParserInstallation.md) and [Parser Developemnt](docs/ParserDevelopment.md) documentation for more info.
- `FileObject.md5` now produces a hex string instead of raw bytes.
- Rearranged the location of some modules (imports do not change however).
- "parserstests" folder has been moved to within the "parsers" folder and renamed "tests".
- Changed `Reporter.managed_tempdir` to a property.
- Updated `construct` helpers to support construct version **2.9.45**.
    - Please see their [transision to 2.9](https://construct.readthedocs.io/en/latest/transision29.html) to see what has changed.
- Reintroduced back some construct 2.8 features that were removed from 2.8, such as `[:]` syntax and default encodings
for String constructs. 
    - These changes will be patched in when using `mwcp.utils.construct` instead of `construct` by itself.
    - Please see the docstring found in [version28.py](mwcp/utils/construct/version28.py) for a full list of changes.
- Added/Updated new `construct` helpers:
    - `ELFPointer` support for ARM. See `mwcp.utils.construct.ARM.ELFPointer`
    - Expanded windows structures.
    - Added support for supplying a callable instead of a dictionary for `Iter`.

### Deprecated
- The `mwcp-tool` and `mwcp-test` tools are deprecated in exchange for using the new `mwcp` tool and
    will be removed in a future version.
    - *NOTE: Some flags will no longer work due to removed features (see Removed section).*
- The `-t` flag is no longer necessary when running tests with `mwcp-test`. 
It is assumed if you are not updating/adding tests.

### Removed
- Removed previously deprecated components:
    - `data`, `filename()`, `pe`, `handle`, `resourcedir`, `parserdir`, `debug()`, `error()` from Reporter class.
    - `mwcp.malwareconfigparser`, `mwcp.malwareconfigreporter`
    - `TerminatedString` in `construct` helpers.
- Removed unused/unpopular Reporter options: 
    - `disablemodulesearch`
    - `disablevaluededup`
    - `disableautosubfieldparsing`
    
### Fixed
- Add ability to set decoder directory from the `run_kordesii_decoder()` function by @ddash-ct ([\#8](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/issues/8))


## [1.4.1] - 2018-10-15
### Changed
- Parsers are now imported on-demand to save initial startup time.
- Small tweaks to logging level.
- Refactored testing utility and force a failed test if a test case or parser is missing.

### Fixed
- Fixed bug where new parsers in the default directory were not getting registered. ([\#6](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/issues/6))


## [1.4.0] - 2018-08-07
### Added
- `elffileutils` helper utility that works similar to `pefileutils`, but for ELF files.
- Timing statistics in `mwcp-test`
- New `construct` helpers: `EpochTime`, `ELFPointer`, `FocusLast`

### Changed
- Logging is now performed using Python's builtin `logging` module.
    - Please see the [README](README.md#logging) for more information.
- Removed "_malwareconfigparser" suffix from example parsers.
- Updated `custombase64` to also support standard alphabet.
    - (Making it suitable as a drop-in replacement of `base64`)
- Updated `construct` helpers: `Delimited`, `Backwards`

### Deprecated
- Deprecated the use of `debug()` and `error()` functions in the Reporter class.
    - Parsers should use the ComponentParser's `logger` or create one at the top of your module.
- Deprecated `TerminatedString` in `construct` helpers. (Please use Padded with CString instead.)

### Fixed
- Reporter will now modify the output filename on a name collision.
- Fixed bug with incorrect csv output formatting when input is a directory.


## [1.3.0] - 2018-05-15
### Added
- Added unit testing using tox and pytest.

### Changed
- Added new standard metadata fields
- Cleaned up mwcp tool
- Updated and added documentation for developing/testing parsers.
- Set DC3-Kordesii as an optional dependency.

### Fixed
- Fixed "unorderable types" error when outputting to csv
- Fixed bugs found in  unit tests.


## [1.2.0] - 2018-04-17
### Added
- Support for multiprocessing in tester.
- Helper function for running [kordesii](https://github.com/Defense-Cyber-Crime-Center/kordesii) decoders in FileObject class.
- Enhancements to Dispatcher.
    - Added option to not output unidentified files.
    - Added option to force overwriting descriptions.

### Changed
- bugfixes and code reformatting
- Pinned construct version to avoid errors that occur with newer versions.

### Removed
- Removed `enstructured` library.


## [1.1.0] - 2018-01-09
### Added
- Initial support for Python 3 from @mlaferrera
- `pefileutils` helper utility
- `custombase64` helper utility
- Dispatcher model, which allows you to split up a parser by their components (Dropper, Implant, etc). (See [documentation](docs/DispatcherParserDevelopment.md) for more information.)
- Support for using setuptool's entry_points to allow for formal python packaging of parsers. (See [documentation](docs/ParserDevelopment.md#formal-parser-packaging) for more information.)
- Added ability to merge results from multiple parsers with the same name but different sources.

### Changed
- Replaced `enstructured` with a `construct` helper utility (See [migration guide](docs/construct.ipynb) for more information.)
- Updated setup.py to install scripts using setuptool's entry_points.
- Renamed "malwareconfigreporter" to "Reporter" and "malwareconfigparser" to "Parser".
    - Old names have been aliased for backwards compatibility but are deprecated.

### Deprecated
- Deprecated use of resourcedir in Reporter.
    - Parser should modify sys.path themselves or properly install the library if it has a dependency.


## 1.0.0 - 2017-04-18
### Added
- Initial contribution.

### Fixed
- Fixed broken markdown headings from @bryant1410


[Unreleased]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.3.1...HEAD
[3.3.1]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.3.0...3.3.1
[3.3.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.2.1...3.3.0
[3.2.1]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.2.0...3.2.1
[3.2.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.1.0...3.2.0
[3.1.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.0.1...3.1.0
[3.0.1]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.0.0...3.0.1
[3.0.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/2.2.0...3.0.0
[2.2.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/2.2.0...2.2.0
[2.1.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/2.0.3...2.1.0
[2.0.3]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/2.0.2...2.0.3
[2.0.2]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/2.0.1...2.0.2
[2.0.1]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/2.0.0...2.0.1
[2.0.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.4.1...2.0.0
[1.4.1]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.4.0...1.4.1
[1.4.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.3.0...1.4.0
[1.3.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.2.0...1.3.0
[1.2.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.0.0...1.1.0
