# deduplication Specification

## Purpose

Shared constants and definitions for UI theming and password generation to eliminate duplicate hard-coded values across packages.

## Requirements

### Requirement: Shared Theme Colors

Color constants MUST be defined in `internal/theme/colors.go` and imported by all packages that render UI colors. Duplicate color definitions outside `internal/theme` MUST be removed.

#### Scenario: Consumer imports theme

- GIVEN a package that renders colors
- WHEN it needs a color constant
- THEN it SHALL import from `internal/theme`

#### Scenario: No duplicates

- GIVEN the codebase
- WHEN searching for color hex values
- THEN duplicates SHALL NOT exist outside `internal/theme`

### Requirement: Shared Password Charset

Password generation charset definitions MUST be defined in `internal/crypto/charset.go` and imported by all packages that generate passwords. Duplicate charset definitions outside `internal/crypto/charset.go` MUST be removed.

#### Scenario: Consumer imports charset

- GIVEN a package that generates passwords
- WHEN it needs a charset
- THEN it SHALL import from `internal/crypto`

#### Scenario: No duplicates

- GIVEN the codebase
- WHEN searching for charset strings
- THEN duplicates SHALL NOT exist outside `internal/crypto/charset.go`
