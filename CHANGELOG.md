# Changelog
All notable changes to this project will be documented in this file.


## [Unreleased]
### Added
- Initial support for Python 3 from @mlaferrera
- Dispatcher mixin, which allows you to split up parser by their components (Dropper, Implant, etc). (See documentation for more information.)

### Changed
- Updated setup.py to install scripts using setuptool's entry_points.
- Renamed malwareconfigreporter to Reporter and malwareconfigparser to Parser
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