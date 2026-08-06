# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Whitelist policy support for all modules (network, process, files, mount)
- Controller module for whitelist generation
- `safeguard controller generate` command with `--output`, `--report`, and `--mode` flags
- Policy validation in config (`blacklist` / `whitelist` modes)
- Path validation for file and mount modules
- CIDR validation for network module
- Extended logging helpers (Warnf, Debugf, Infof, Errorf)
- DNS proxy feature for domain-based network restriction
- Container-targeted restriction mode for all modules
- JSON report output for controller-generated whitelists
- Comprehensive test suite covering all packages

### Changed
- Default config now includes deny fields for process
- Improved error messages for config validation
- BPF map operations now use dedicated manager types per module
- Controller service now supports custom report paths

### Fixed
- Policy mode enforcement in BPF programs
- DNS proxy upstream resolution error handling
- Mount restriction source path matching for bind mounts
- Network CIDR truncation warning for BPF map key limits

## [0.0.10] - 2026-04-01

### Added
- Initial release
- Network restriction module (CIDR-based allow/deny)
- File access restriction module (path-based allow/deny)
- Mount restriction module (source path-based deny)
- Process restriction module (executable path-based allow/deny)
- DNS proxy feature for domain-based filtering
- Monitor and block modes for all restriction modules
- Host-wide and container-targeted restriction scopes
- YAML-based configuration with validation
- JSON and text log format support

### Security
- BPF LSM-based enforcement for all restriction modules
- Kernel version and BTF compatibility checks at startup
- Root privilege requirement enforcement
