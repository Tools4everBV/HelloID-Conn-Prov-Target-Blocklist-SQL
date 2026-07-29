# HelloID-Conn-Prov-Target-Blacklist-SQL

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Blacklist-SQL/blob/main/Logo.png?raw=true width="500" height="300">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Blacklist-SQL](#helloid-conn-prov-target-blacklist-sql)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
    - [Use Cases](#use-cases)
  - [Supported features](#supported-features)
  - [Getting started](#getting-started)
    - [HelloID Icon URL](#helloid-icon-url)
    - [Requirements](#requirements)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
    - [Account Reference](#account-reference)
  - [Remarks](#remarks)
  - [Development resources](#development-resources)
    - [Available lifecycle actions](#available-lifecycle-actions)
    - [Additional scripts](#additional-scripts)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

HelloID-Conn-Prov-Target-Blacklist-SQL is a target connector that writes user attribute values to an SQL database-based blacklist. These values can later be used to prevent reuse, for example of `sAMAccountName`, `email`, or `userPrincipalName`. The blacklist is used in combination with the uniqueness check feature of other connectors (e.g., Active Directory) to ensure attribute values remain unique across the organization.

### Use Cases

This connector is designed to solve common identity management challenges:

1. **Preventing attribute reuse**: When an employee leaves the organization, their email address, username, or UPN is blocked from being immediately reassigned. This prevents confusion, misdirected emails, and security issues.

2. **Organizational uniqueness enforcement**: Even if your HR system doesn't track historical employees, the blacklist maintains a record of all previously used values, ensuring no two people (past or present) can have the same identifier.

3. **Controlled value recycling**: After a configurable retention period (e.g., 365 days), values can be made available for reuse, balancing security with practical namespace management.

4. **Cross-system validation**: Works seamlessly with HelloID's built-in connectors (like Active Directory) to validate uniqueness before account creation, preventing provisioning errors.

5. **Temporary departures**: When an employee returns after a leave of absence, their original values can be automatically restored if still within the retention period.

6. **Multi-attribute validation**: Supports checking multiple attributes simultaneously (email, UPN, proxy addresses) with cross-checking capabilities to catch conflicts across different attribute types.

## Supported features

The following features are available:

| Feature                               | Supported | Notes                                                      |
| ------------------------------------- | --------- | ---------------------------------------------------------- |
| Account Lifecycle                     | ✅         | Create, Update, Delete (soft-delete with retention period) |
| Permissions                           | ❌         | Not applicable for blacklist connector                     |
| Resources                             | ❌         | Not applicable for blacklist connector                     |
| Entitlement Import: Accounts          | ❌         | Not applicable for blacklist connector                     |
| Entitlement Import: Permissions       | ❌         | Not applicable for blacklist connector                     |
| Governance Reconciliation Resolutions | ❌         | Not applicable for blacklist connector                     |

## Getting started

### HelloID Icon URL

URL of the icon used for the HelloID Provisioning target system.

```
https://raw.githubusercontent.com/Tools4everBV/HelloID-Conn-Prov-Target-Blacklist-SQL/refs/heads/main/Icon.png
```

### Requirements

- HelloID Provisioning agent (cloud or on-premises)
- Available MS SQL Server database (external server or local SQL Express instance)
- Database table created using the `createTableBlacklist.sql` script in `SupportingFiles` folder
- Database access rights for the agent's service account or SQL-authenticated account
- The client is responsible for populating the blacklist database with any previous data. HelloID will only manage and add the data for the persons handled by provisioning.

### Connection settings

The following settings are required to connect to the SQL database.

| Setting                | Description                                                                                                                                                                                                                                                                  | Mandatory |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| Connection string      | String value of the connection string used to connect to the SQL database                                                                                                                                                                                                    | Yes       |
| Table                  | String value of the table name in which the blacklist values reside                                                                                                                                                                                                          | Yes       |
| Username               | String value of the username of the SQL user to use in the connection string                                                                                                                                                                                                 | No        |
| Password               | String value of the password of the SQL user to use in the connection string                                                                                                                                                                                                 | No        |
| RetentionPeriod (days) | **Critical setting**: Number of days a deleted value remains blocked before it can be reused. Common values: `365` (1 year), `730` (2 years), or `999999` (permanent blocking). This protects against immediate reuse while allowing eventual recycling of namespace values. | Yes       |

### Correlation configuration

The correlation configuration is not used or required in this connector.

### Field mapping

The field mapping can be imported by using the `fieldMapping.json` file.

- `employeeId` is only mapped for the **Create** action
- Attributes (Mail, SamAccountName, UserPrincipalName) are mapped for **Create**, **Update**, and **Delete** actions
- All fields use `StoreInAccountData: true`

### Account Reference

The account reference is populated with the `employeeId` property during the Create action.

**Why employeeId is important**: The `employeeId` serves as the unique identifier linking blacklist entries to specific individuals. This is critical for:

- **Ownership tracking**: Determines who "owns" each blocked value
- **Automatic restoration**: When a person is re-enabled, their previous values can be restored because the system knows which values belonged to them
- **Conflict prevention**: If a value is already in use by another employeeId (and within retention period), the system prevents reassignment
- **Multi-value support**: One person can have multiple blocked attributes (email, UPN, proxy addresses) all tied to their employeeId
- **Audit trail**: Provides clear history of which values were assigned to which employees and when

## Remarks

> [!NOTE]
> This connector is designed to work in combination with the uniqueness check feature of other connectors (like Active Directory) to ensure attribute values remain unique across the organization.

- **Soft-delete with retention**: When a person is deleted, the `whenDeleted` timestamp is set. The value remains blocked for the configured retention period.
- **Automatic restore**: If a person is re-enabled and their previous attribute value is still blocked, the Create action automatically restores it by clearing the `whenDeleted` timestamp.
- **Retention period configuration**: Use `RetentionPeriod (days)` to specify how long values remain blocked after deletion. Setting this to `999999` effectively makes the retention permanent.
- **Self-usage control**: The `checkOnExternalSystemsAd.ps1` script includes an `$allowSelfUsage` configuration. When set to `$false`, even a person's own existing values are treated as non-unique, forcing complete value regeneration. This is useful for migration scenarios or when implementing new naming conventions.
- **Multiple records handling**: The Update action will issue a warning if multiple records with the same `attributeName` and `attributeValue` are found.
- **Cross-check validation**: The `checkOnExternalSystemsAd.ps1` script supports `crossCheckOn` configuration to validate uniqueness across different attribute types (e.g., checking if an email address already exists as a proxy address).
- **keepInSyncWith functionality**: When configured, non-unique status cascades across related fields automatically.
- **Skip optimization**: Once a field is marked non-unique, redundant database queries are automatically skipped.
- **SQL query safety**: All scripts use proper SQL escaping for single quotes to prevent SQL injection.

## Development resources

### Available lifecycle actions

The following lifecycle actions are available:

| Action | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Create | **Creates or restores blacklist records** for each configured attribute. If a value already exists in the blacklist: (1) owned by the same person - clears `whenDeleted` to reactivate, (2) owned by another person but retention period expired - updates `employeeId` and clears `whenDeleted` to reassign, (3) owned by another person within retention period - throws error. If value doesn't exist, creates a new record with `whenCreated` timestamp. |
| Update | **Maintains blacklist records** for each configured attribute. Similar logic to Create: can create new records if missing, reactivate previously deleted values (clear `whenDeleted`), or reassign expired values to current person. Updates `whenUpdated` timestamp. Does **not** modify the `attributeValue` itself - only ownership and timestamps.                                                                                                       |
| Delete | **Soft-deletes blacklist records** by setting `whenDeleted` and `whenUpdated` timestamps. Records remain in the database but are marked as deleted. After the configured retention period expires, these values become available for reuse by other persons. Does **not** physically remove rows from the database.                                                                                                                                          |

### Additional scripts

Beyond the standard lifecycle scripts, this connector includes specialized scripts:

| Script                                  | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `CheckOnExternalSystems/checkOnExternalSystemsAd.ps1` and `CheckOnExternalSystems/checkOnExternalSystemsAdAndSql.ps1` | **Uniqueness validation scripts** - Validate proposed attribute values before provisioning. Full configuration and usage details are documented in `CheckOnExternalSystems/README.md`. |
| `SupportingFiles/createTableBlacklist.sql` and `SupportingFiles/importInitialDataFromCsv.ps1` | **Database helper files** - SQL table setup and optional initial CSV import tooling. Full setup and usage details are documented in `SupportingFiles/README.md`. |
| `GenerateUniqueData/example.create.ps1` | **Legacy example script** - Demonstrates how to generate unique values by querying the SQL blacklist database in older PowerShell v1 connectors. While this is legacy code, it can be adapted for scenarios requiring custom unique value generation (e.g., employee numbers, random identifiers). Not required for standard V2 connector operation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

For detailed configuration of the uniqueness validation scripts, see `CheckOnExternalSystems/README.md`.

For database setup, table structure, and initial CSV import guidance, see `SupportingFiles/README.md`.

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/.
