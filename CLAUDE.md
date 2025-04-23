# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build/Test Commands
- Check code: `cargo make check`
- Run tests: `cargo make test`
- Run unit tests only: `cargo make unit`
- Run integration tests: `cargo make integration`
- Run single test: `cargo nextest run --test test_name --package pkg_name`
- Generate test keys: `cargo make gen-keys`
- Format code: `cargo fmt`

## Code Style Guidelines
- Line width: 70 characters maximum
- Use snake_case for variables/functions, CamelCase for types/enums
- Group imports logically (std lib, external crates, internal modules)
- Use `thiserror` for error types with descriptive messages
- Return Result types with `?` operator for error propagation
- Place unit tests in `#[cfg(test)]` modules in same file as code
- Integration tests go in dedicated `integration_tests` crate
- Wrap long types with type aliases for readability
- Document public API with `///` and modules with `//!` comments
- Use feature gates (`#[cfg(feature = "...")]`) for conditional compilation