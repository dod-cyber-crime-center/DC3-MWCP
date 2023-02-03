# Changelog
All notable changes to this project will be documented in this file.

## [3.10.1] - 2023-02-03

### Added
- [packaging](https://pypi.org/project/packaging/) dependency

### Fixed
- Use `packaging.version` for version comparison with test results


## [3.10.0] - 2023-01-25

### Added
- Added `.with_encoding()` function on `EncryptionKey` metadata elements for telling MWCP how to display encryption keys in the text report.

### Changed
- Improved handling of displaying decodable encryption keys.
- YaraRunner will now skip compiling rule files without 'mwcp' meta defined.
- Parser test cases can now be added or updated with recursive YARA matching by adding the `--recursive` flag to the `mwcp test` command.

### Fixed
- Fixed IDA project file not being output for 64-bit samples.
- Fixed issue with duplicate residual files when using recursive YARA matching.
- Fixed memory leak that occurs when processing multiple runs subsequently in the same process.


## [3.9.0] - 2022-11-22
### Added
- Added `FileObject.ext` property for getting and setting the file's extension.
- Added builtin parsers.
- Added YARA matching capability to automatically determine which parser(s) to run. (see [documentation](README.md#yara-matching)) 

### Changed
- Improved aliasing in parser configuration file.
  - Aliases can now be used for pointing to individual parser components. (e.g. `PDF: .Document`) This helps to avoid the need to create parser groups just for pointing to a single parser component.
  - External pointers are no longer limited to just inside parser groups. Aliases can now also point to external parsers (e.g. `DecoyDOC: dc3:Decoy.DOC`) 

### Removed
- Removed legacy `mwcp.Reporter` object.  
- Removed `cleanup_temp_files` option from `mwcp.Runner` object.
- Removed `temp_directory` option from `mwcp.Runner` object.
- Removed deprecated components from `mwcp.Runner` (these components should be pulled from the generated Report object instead):
  - `.managed_tempdir`
  - `.add_metadata()`
  - `.input_file`
  - `.metadata`
  - `.output_file()`
  - `.errors`
  - `.run_parser()`
  - `.print_report()`
  - `.print_report()`
  - `.get_output_text()`
  - `.fields`
- Removed deprecated `.managed_tempdir` from `mwcp.Report` object.
- Removed `--cleanup` CLI flag.


## [3.8.0] - 2022-09-14

### Added
- Added `Report.strings()` convenience function for obtaining reported decoded strings.
- Added option to produce external string reports for decoded strings instead of being included in the main report.
  -  Reports will be added as supplemental files with original name suffixed with `_strings.json` and `_strings.txt`.
  - Use the `--string-report` flag to enable this in the CLI tool.
  - Use the `external_strings` field to enable this in the server.

### Changed
- `DecodedString` metadata is now included in legacy report output.

### Fixed
- Fixed issue with `Path2.from_segments()` ignoring previous segments when another segment starts with a slash.
- Fixed issue with throwing of `UnableToParse` sometimes causing the residual file not to be reported.
- Files for which a parser throws an `UnableToParse` and end up not getting identified by any other parsers will
  now appropriately be identified as "Unidentified file". (NOTE: This change may cause previous test cases to fail.)
- Fixed bug with `Report.get()` and `Report.iter()` returning elements that don't match requested type.
- Fixed bug in STIX output when a parser added a tag to a piece of metadata that translated to an observed-string.


## [3.7.0] - 2022-06-28

### Added
- STIX 2.1 output format that includes three SCO extensions and one property extension.  This generates a STIX package containing the results of the full analysis.
  - SCO Extensions
    - observed-string
    - crypto-currency-address
    - symmetric-encryption
  - Property Extensions
    - extension-definition--b84c95f5-d48d-4e4a-b723-7d209a02deb9 -- RSA Private key extension for x509-certificate
- Added `Path2` metadata element which simplifies fields from `Path` and better supports non-Windows paths.
  - `name` and `directory_path` are removed in favor of just having a `path` element.
  - Added `posix` field to indicated if path is Posix or Windows based.
  - Added `.from_segments()` and `.from_pathlib_path()` constructors.
- Added `derivation` field to `FileObject` object and `File` metadata element.
- Added `FileObject.disassembly()` function for obtaining Dragodis dissassembler.

### Fixed
- AttributeError that can occur during testing if a Registry without a path was reported.
- Disables skipping recursive files to avoid a breaking bug with greedy parsers.
  - This is temporary until a proper fix can be implemented.
- Fixed issue with process stalling when integer is provided in a bytes metadata field.

### Deprecated
- `Path` is deprecated in favor of `Path2`.
  - NOTE: Once deprecations are removed, `Path2` will be renamed back to `Path`.


## [3.6.2] - 2022-04-04

### Fixed
- config.load now accepts file_path as a string on pathlib.Path (@rhartig-ct)
  - In 3.6.1 config.load was updated to take pathlib.Path, but mwcp.tools.server still used string

## [3.6.1] - 2022-03-28

### Fixed
- AttributeError that can occur during testing if a Registry without a path was reported.
- Disables skipping recursive files to avoid a breaking bug with greedy parsers.
  - This is temporary until a proper fix can be implemented.


## [3.6.0] - 2022-03-23

### Added
- `Command` metadata element.
- `CryptoAddress` metadata element.
- `Report.add_tag()` which allows adding tags to the report itself.
- Added ability to include `TAGS` attribute in `Parser` classes.
- Added ability to include direct aliases in parser config by simply providing the name. (e.g. `FooAlias: Foo`)
- Added `.from_PEM()`, `.from_DER()`, `.from_BLOB()`, and `.from_XML()` construction methods for `RSAPublicKey` and `RSAPrivateKey` metadata elements.
- Added `Registry2` metadata element which includes the following changes from `Registry`:
  - `path` attribute has been removed.
  - `key` attribute has been renamed to `subkey` and no longer includes the root hive key.
  - `hive` attribute has been added which is casted to a `metadata.RegistryHive` enum type. `hive` will automatically be extracted if not provided but included in `subkey`.
  - `data_type` attribute has been added, which is a `metadata.RegistryDataType` enum type. `data_type` will automatically be inferred from the data type of `data` if not provided.
  - Added a `.from_path()` constructor to generate an entry from a full path.
- Added `mwcp download` CLI command to download sample files from the malware repo.
  - Includes `--last-failed` flag to download samples from previously failed tests.

### Changed
- Enable construct Adapters for `EpochTime`, `SystemTime`, and `FileTime` to accept a timezone, and add default helpers for UTC. (@ddash-ct)
- Renamed `Dispatcher.add_to_queue()` to `Dispatcher.add()`.
- Added full parameters to `C2URL` metadata function to match `URL`.
- Updated `mwcp test` CLI command:
  - Condensed diff and removed extraneous information for failed test reports.
  - Added `--full-diff` flag to get the full diff. 
  - Added `--last-failed` flag to rerun only previously failed test cases.
    - Can also be combined with `--update` flag to update only previously failed tests.

### Fixed
- Fixed issue with `Version` table in text report stripping off 0's
- Added detection of recursive loop parsing the same file.
  - Duplicate files will automatically be tagged with `duplicate` and not be parsed.
- If a parser dispatches the file it is currently processing, it will now be ignored.

### Deprecated
- `Dispacher.add_to_queue()` is deprecated in favor of `Dispatcher.add()`.
- `Registry` is deprecated in favor of `Registry2`. 
  - NOTE: Once deprecations are removed, `Registry2` will be renamed back to `Registry`.


## [3.5.0] - 2022-01-11

### Added
- Added `--command` flag to `mwcp test`. This flag will provide the user with a printout of the pytest 
command that would be run given the other options provided in the command line.

### Changed
- The `--no-legacy` flag is now set by default for `mwcp parse` and `mwcp test` commands. 
  - **If you still need to use legacy testing or parse results, you must now explicitly include the `--legacy` flag.**
  - *This does not affect the web service tool. For now, legacy mode is still set as default.*
- Updated the `Other` metadata element to accept string, bytes, integers, or booleans as values.
  - Also, added new field `value_format` to show the data type of the value. This helps to avoid any ambiguities in json results.
- The "Tags" column in the generated report won't be shown if there are no tags in the table.

### Fixed
- Fixed UnicodeDecodeError that can occur when printing a report with nested metadata elements. ([\#31](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/issues/31))
- Include missing "Mode" column from EncryptionKey report tables.
- Fixed rendering for values with line breaks in the HTML report output.
- Removed obfuscated powershell examples from poshdeob causing a VT hit. ([\#32](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/issues/32))


## [3.4.0] - 2021-10-06

### Added
- Added a formal schema for (non-legacy) JSON report output which can be found in [schema.json](/mwcp/config/schema.json)
- Added `mwcp schema` CLI command to generate the current schema.
- Added [documentation](/README.md#schema) on how to create your own custom reportable metadata element.

### Changed
- Updated server dependencies.
- The `input_file` and `residual_file` metadata types are now both referred to as `file`.
- Legacy versions of `uuid` and `interval` metadata types are now typed as `uuid_legacy` and `interval_legacy`
  respectively. This was done to ensure a proper schema can be generated.
- Updated testing utility to ensure test cases older than 3.3.3 handle changes accordingly.
- Updated the regular expression in the `URL` metadata object allowing it to succeed with optional schema
- `URL` metadata object no longer defaults the network protocol to `tcp` for embedded `socket`

### Fixed
- Fixed `EncryptionKey` report formatting to display text representation when key is printable (not just ascii).
- The `--testcase-dir` flag when running `mwcp test` in non-legacy mode will now handle any directory structure.


## [3.3.2] - 2021-07-19

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
- Fixed bug with differently ordered tags causing test cases to fail.

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


[Unreleased]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.10.1...HEAD
[3.10.1]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.10.0...3.10.1
[3.10.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.9.0...3.10.0
[3.9.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.8.0...3.9.0
[3.8.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.7.0...3.8.0
[3.7.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.6.2...3.7.0
[3.6.2]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.6.1...3.6.2
[3.6.1]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.6.0...3.6.1
[3.6.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.5.0...3.6.0
[3.5.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.4.0...3.5.0
[3.4.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.3.2...3.4.0
[3.3.2]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/3.3.1...3.3.2
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
