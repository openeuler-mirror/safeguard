# Changelog

## [Unreleased]

### Added
- Whitelist policy support for all modules (network, process, files, mount)
- Controller module for whitelist generation
- `culinux controller generate` command
- Policy validation in config
- Path validation for file and mount modules
- CIDR validation for network module
- Extended logging helpers (Warnf, Debugf, Infof, Errorf)

### Changed
- Default config now includes deny fields for process
- Improved error messages for config validation

### Fixed
- Policy mode enforcement in BPF programs

## [0.0.10] - 2026-04-01

### Added
- Initial release
- Network restriction module
- File access restriction module
- Mount restriction module
- Process restriction module
- DNS proxy feature
