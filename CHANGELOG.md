# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.2.0] - 2026-08-03

### Added

- Added support for connecting to a `Azure SQL` database.
- Added `UniquenessCheck/uniquenessCheckEntraIdChecksSqlAndEntraId.ps1` for combined uniqueness validation against SQL and Microsoft Entra ID.
- Added `UniquenessCheck/README.md` with usage and configuration details for the uniqueness check scripts.
- Added `SupportingFiles/createTableBlocklist.sql` as the renamed SQL table setup script.

### Changed

- Renamed blocklist uniqueness scripts from `CheckOnExternalSystems/*` to `UniquenessCheck/*` and updated documentation references accordingly.
- Replaced terminology across the repository from Blacklist/blacklist to Blocklist/blocklist.

## [2.1.0] - 2026-07-28

### Added

- New combined uniqueness check script `checkOnExternalSystemsAdAndSql.ps1` to validate values against both SQL blocklist and Active Directory in one flow, including cross-check support and keep-in-sync behavior.
- New initial import utility `importInitialDataFromCsv.ps1` for loading blocklist data from CSV, enriching entries via AD lookup, and auto-adding `UserPrincipalName` rows for mail-based input.
- Added separated folders for `CheckOnExternalSystems` and `SupportingFiles` including a separated `README.md`.

### Changed

- Updated SQL table definition in `createTableBlocklist.sql` so `employeeId` allows `NULL`, aligning with import and lookup scenarios where no employee ID is available.
- Added a filtered index on `employeeId` (`IX_blocklist_2`) to optimize lookups for populated employee IDs while keeping nullable records supported.

## [2.0.2] - 2026-04-01

### Changed

- Added explicit correlation attribute validation in `checkOnExternalSystemsAd.ps1` to fail fast when `accountFieldName` is missing, not mapped in the account object, or mapped without a value
- Expanded correlation attribute guidance in `checkOnExternalSystemsAd.ps1` configuration comments and in the README with an IMPORTANT callout that the correlation field must be mapped for all operations where uniqueness checks are enabled (create, update, etc.)

### Fixed

- Corrected uniqueness result evaluation in `checkOnExternalSystemsAd.ps1` by using `$selectRowCount` instead of `@($querySelectResult).count`, improving reliability for SQL query result counting

## [2.0.1] - 2026-04-01

### Changed

- Added IMPORTANT callout in README documenting field mapping requirement for correlation attribute (`accountFieldName`) in `checkOnExternalSystemsAd.ps1` configuration, emphasizing that it must be mapped for ALL operations (create, update, etc.) where the uniqueness check is used

### Fixed

- Corrected count check in checkOnExternalSystemsAd.ps1 to use `$selectRowCount` variable instead of `@($querySelectResult).count` for more reliable result counting

## [2.0.0] - 2026-01-07

This is a major release of HelloID-Conn-Prov-Target-Blocklist-SQL with significant enhancements to match the CSV blocklist connector functionality and Tools4ever V2 connector standards, plus major improvements to code maintainability, configurability, and operational transparency.

### Added

- Retention period support with configurable duration for deleted values and automatic expiration logic
- `retentionPeriod` configuration parameter to specify how many days deleted values remain blocked before reuse
- Cross-check validation via `crossCheckOn` configuration to validate uniqueness across different attribute types (e.g., checking if an email exists as a proxy address)
- `keepInSyncWith` functionality to replace legacy `syncIterations` approach, providing automatic cascading of non-unique status across related fields
- `$allowSelfUsage` configuration in `checkOnExternalSystemsAd.ps1` to control whether persons can reuse their own values (replaces `$excludeSelf`)
- `$fieldsToCheck` object-based configuration in `checkOnExternalSystemsAd.ps1` to replace simple `$attributeNames` array
- Skip optimization to automatically skip redundant database queries once a field is marked non-unique
- Action types `OtherEmployeeId` and `MultipleFound` for enhanced error handling with detailed error messages
- Database columns `whenCreated` and `whenUpdated` with datetime2(7) precision for timestamp tracking
- PowerShell-based timestamp generation using `Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fff"` for consistent datetime2(7) precision
- Detailed audit logging in Update and Delete actions showing exactly which fields are modified and their new values
- `#region Configuration` block in `checkOnExternalSystemsAd.ps1` for better code organization
- README section "Configuring checkOnExternalSystemsAd.ps1" with detailed configuration examples
- README warnings for retention period synchronization and initial configuration requirements
- README use cases section explaining practical applications of the blocklist connector
- README supported features table documenting available capabilities

### Changed

- Create script restructured to match CSV connector format with improved action calculation logic
- Update script aligned with Create script logic including retention period validation
- Delete script rewritten to process per-attribute instead of bulk updates
- `whenDeleted` column type changed from `date` to `datetime2(7)` for precision and consistency
- checkOnExternalSystemsAd.ps1 field checking logic enhanced with retention period awareness and cross-attribute validation
- fieldMapping.json updated to match CSV structure (employeeId only for Create, attributes for Create/Update/Delete) with Complex mapping mode using conditional logic
- Credential initialization in checkOnExternalSystemsAd.ps1's Invoke-SQLQuery function now properly creates SqlCredential object
- Configuration comments expanded with detailed explanations of field checking logic, cross-checking, and field synchronization
- README lifecycle action descriptions enhanced with detailed scenario coverage including retention period behavior
- README additional scripts descriptions improved with retention period logic details
- Logging changed from Write-Information intentions to result-based logging with adjusted log levels (unique=Information, non-unique=Warning)
- Audit logs moved inside non-dryRun blocks to prevent audit entries during preview mode
- SQL UPDATE queries simplified to only modify `whenDeleted` and `whenUpdated` fields
- Account reference moved to absolute top of create script for consistency
- Update and Delete actions refactored to build SET clauses dynamically from object properties
- Logging in checkOnExternalSystemsAd.ps1 improved to distinguish between self-usage scenarios and retention period validations

### Deprecated

- Legacy syncIterations and syncIterationsAttributeNames approach replaced by keepInSyncWith configuration

### Removed

- `whenDeleted` field from fieldMapping.json (now managed internally by scripts)
- Unnecessary Write-Information statements for action intentions

## [1.1.0] - 2024-12-12

### Added

- PowerShell V2 connector support with improved structure
- Enhanced field mapping configuration
- Improved error handling and logging

### Changed

- Migrated from legacy PowerShell V1 to PowerShell V2 connector format
- Updated connector structure to follow V2 standards
- Improved code organization and maintainability

## [1.0.0] - 2024-05-17

### Added

- Initial release of HelloID-Conn-Prov-Target-Blocklist-SQL
- Basic create, update, and delete lifecycle actions
- SQL database integration for blocklist management
- Support for tracking employeeId, attributeName, and attributeValue
- Configuration for connection string and table settings
- Field mapping for SamAccountName, UserPrincipalName, and employeeId
- Basic uniqueness checking script for Active Directory integration
- Example script for generating unique data
- SQL table creation script

### Changed

- N/A (initial release)

### Fixed

- N/A (initial release)
