# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed
- Updated pefileutils to support pefile version 2018.4.18


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


[Unreleased]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/2.0.2...HEAD
[2.0.2]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/2.0.1...2.0.2
[2.0.1]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/2.0.0...2.0.1
[2.0.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.4.1...2.0.0
[1.4.1]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.4.0...1.4.1
[1.4.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.3.0...1.4.0
[1.3.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.2.0...1.3.0
[1.2.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.0.0...1.1.0
