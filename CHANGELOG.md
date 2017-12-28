# Changelog
All notable changes to this project will be documented in this file.


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


[Unreleased]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.1.0..HEAD
[1.1.0]: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP/compare/1.0.0..1.1.0