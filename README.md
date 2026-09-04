# HelloID-Conn-Prov-Target-Blocklist-SQL

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Blocklist-SQL/blob/main/Logo.png?raw=true width="500" height="300">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Blocklist-SQL](#helloid-conn-prov-target-blocklist-sql)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
    - [Use Cases](#use-cases)
  - [Supported features](#supported-features)
  - [Getting started](#getting-started)
    - [HelloID Icon URL](#helloid-icon-url)
    - [Requirements](#requirements)
    - [Connection settings](#connection-settings)
    - [SQL authentication](#sql-authentication)
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

HelloID-Conn-Prov-Target-Blocklist-SQL is a target connector that writes user attribute values to an SQL database-based blocklist. These values can later be used to prevent reuse, for example of `sAMAccountName`, `email`, or `userPrincipalName`. The blocklist is used in combination with the uniqueness check feature of other connectors (e.g., Active Directory) to ensure attribute values remain unique across the organization.

### Use Cases

This connector is designed to solve common identity management challenges:

1. **Preventing attribute reuse**: When an employee leaves the organization, their email address, username, or UPN is blocked from being immediately reassigned. This prevents confusion, misdirected emails, and security issues.

2. **Organizational uniqueness enforcement**: Even if your HR system doesn't track historical employees, the blocklist maintains a record of all previously used values, ensuring no two people (past or present) can have the same identifier.

3. **Controlled value recycling**: After a configurable retention period (e.g., 365 days), values can be made available for reuse, balancing security with practical namespace management.

4. **Cross-system validation**: Works seamlessly with HelloID's built-in connectors (like Active Directory) to validate uniqueness before account creation, preventing provisioning errors.

5. **Temporary departures**: When an employee returns after a leave of absence, their original values can be automatically restored if still within the retention period.

6. **Multi-attribute validation**: Supports checking multiple attributes simultaneously (email, UPN, proxy addresses) with cross-checking capabilities to catch conflicts across different attribute types.

## Supported features

The following features are available:

| Feature                               | Supported | Notes                                                      |
| ------------------------------------- | --------- | ---------------------------------------------------------- |
| Account Lifecycle                     | ✅         | Create, Update, Delete (soft-delete with retention period) |
| Permissions                           | ❌         | Not applicable for blocklist connector                     |
| Resources                             | ❌         | Not applicable for blocklist connector                     |
| Entitlement Import: Accounts          | ❌         | Not applicable for blocklist connector                     |
| Entitlement Import: Permissions       | ❌         | Not applicable for blocklist connector                     |
| Governance Reconciliation Resolutions | ❌         | Not applicable for blocklist connector                     |

## Getting started

### HelloID Icon URL

URL of the icon used for the HelloID Provisioning target system.

```
https://raw.githubusercontent.com/Tools4everBV/HelloID-Conn-Prov-Target-Blocklist-SQL/refs/heads/main/Icon.png
```

### Requirements

- HelloID Provisioning agent (cloud or on-premises)
- Available MS SQL Server database (external server or local SQL Express instance or Azure SQL)
- Database table created using the `createTableBlocklist.sql` script in `SupportingFiles` folder
- **For local SQL authentication**: Database access rights for a SQL-authenticated account (username/password)
- **For Azure SQL authentication**: An Entra ID app registration with a certificate and the appropriate database role assignments (see [Azure SQL authentication](#azure-sql-authentication))
- The client is responsible for populating the blocklist database with any previous data. HelloID will only manage and add the data for the persons handled by provisioning.

### Connection settings

The following settings are required to connect to the SQL database.

| Setting                                    | Description                                                                                                                                                                                                                                                                                | Mandatory                         |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------- |
| Connection string                          | The connection string used to connect to the SQL database. For local SQL: `Server=<server>;Database=<database>;Integrated Security=True;`. For Azure SQL: `Server=<server>.database.windows.net,1433;Database=<database>;Encrypt=True;TrustServerCertificate=False;Connection Timeout=25;` | Yes                               |
| Table                                      | The table name in which the blocklist values reside                                                                                                                                                                                                                                        | Yes                               |
| Retention Period (days)                    | **Critical setting**: Number of days a deleted value remains blocked before it can be reused. Common values: `365` (1 year), `730` (2 years), or `999999` (permanent blocking). This protects against immediate reuse while allowing eventual recycling of namespace values.               | Yes                               |
| Username                                   | The username of the SQL user. Only used when `Use Azure SQL authentication` is disabled.                                                                                                                                                                                                   | No                                |
| Password                                   | The password of the SQL user. Only used when `Use Azure SQL authentication` is disabled.                                                                                                                                                                                                   | No                                |
| Use Azure SQL authentication               | When enabled, the connector uses a certificate to retrieve an access token for Azure SQL authentication (MS Entra ID).                                                                                                                                                                     | No                                |
| App Registration Directory (tenant) ID     | The Directory (tenant) ID of the Entra ID app registration used for Azure SQL authentication.                                                                                                                                                                                              | Yes (when Azure SQL auth enabled) |
| App Registration Application (client) ID   | The Application (client) ID of the Entra ID app registration used for Azure SQL authentication.                                                                                                                                                                                            | Yes (when Azure SQL auth enabled) |
| App Registration Certificate Base64 String | The Base64-encoded certificate (.pfx) associated with the Entra ID app registration.                                                                                                                                                                                                       | Yes (when Azure SQL auth enabled) |
| App Registration Certificate Password      | The password of the certificate used in the Entra ID app registration.                                                                                                                                                                                                                     | Yes (when Azure SQL auth enabled) |

### SQL authentication

This connector supports two authentication methods for connecting to the SQL database:

**Local SQL authentication** (default): Uses integrated security or a username and password.

**Azure SQL authentication**: Uses an Entra ID app registration with a certificate to obtain an OAuth 2.0 access token scoped to `https://database.windows.net`. Set `Use Azure SQL authentication` to `true` (enabled) and configure the following prerequisites:

[Documentation](https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-service-principal-tutorial?view=azuresql)

1. **Create an Entra ID app registration** and note its Directory (tenant) ID and Application (client) ID.
2. **Upload a certificate** to the app registration (used to sign JWT assertions for token acquisition).
3. **Grant the app registration access** to the Azure SQL database using the following T-SQL (run as a database admin user):
   ```sql
   CREATE USER [<app-registration-name>] FROM EXTERNAL PROVIDER;
   ALTER ROLE db_datareader ADD MEMBER [<app-registration-name>];
   ALTER ROLE db_datawriter ADD MEMBER [<app-registration-name>];
   ```
4. **Export the certificate** as a Base64-encoded string (`.pfx` format) and provide it together with its password in the connector configuration.

> [!NOTE]
> When `Use Azure SQL authentication` is enabled, the `Username` and `Password` settings are ignored.

### Correlation configuration

The correlation configuration is not used or required in this connector.

### Field mapping

The field mapping can be imported by using the `fieldMapping.json` file.

- `employeeId` is only mapped for the **Create** action
- Attributes (Mail, SamAccountName, UserPrincipalName) are mapped for **Create**, **Update**, and **Delete** actions
- All fields use `StoreInAccountData: true`

### Account Reference

The account reference is populated with the `employeeId` property during the Create action.

**Why employeeId is important**: The `employeeId` serves as the unique identifier linking blocklist entries to specific individuals. This is critical for:

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
- **Self-usage control**: The `uniquenessCheckAdChecksSql.ps1` script includes an `$allowSelfUsage` configuration. When set to `$false`, even a person's own existing values are treated as non-unique, forcing complete value regeneration. This is useful for migration scenarios or when implementing new naming conventions.
- **Multiple records handling**: The Update action will issue a warning if multiple records with the same `attributeName` and `attributeValue` are found.
- **Cross-check validation**: The `uniquenessCheckAdChecksSql.ps1` script supports `crossCheckOn` configuration to validate uniqueness across different attribute types (e.g., checking if an email address already exists as a proxy address).
- **keepInSyncWith functionality**: When configured, non-unique status cascades across related fields automatically.
- **Skip optimization**: Once a field is marked non-unique, redundant database queries are automatically skipped.
- **SQL query safety**: All scripts use proper SQL escaping for single quotes to prevent SQL injection.
- **Azure SQL authentication**: When `Use Azure SQL authentication` is enabled, the connector obtains an OAuth 2.0 access token from MS Entra ID using a certificate-based client assertion (JWT). This token is passed directly to the SQL connection and is valid for 1 hour. The username and password settings are ignored in this mode.

## Development resources

### Available lifecycle actions

The following lifecycle actions are available:

| Action | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Create | **Creates or restores blocklist records** for each configured attribute. If a value already exists in the blocklist: (1) owned by the same person - clears `whenDeleted` to reactivate, (2) owned by another person but retention period expired - updates `employeeId` and clears `whenDeleted` to reassign, (3) owned by another person within retention period - throws error. If value doesn't exist, creates a new record with `whenCreated` timestamp. |
| Update | **Maintains blocklist records** for each configured attribute. Similar logic to Create: can create new records if missing, reactivate previously deleted values (clear `whenDeleted`), or reassign expired values to current person. Updates `whenUpdated` timestamp. Does **not** modify the `attributeValue` itself - only ownership and timestamps.                                                                                                       |
| Delete | **Soft-deletes blocklist records** by setting `whenDeleted` and `whenUpdated` timestamps. Records remain in the database but are marked as deleted. After the configured retention period expires, these values become available for reuse by other persons. Does **not** physically remove rows from the database.                                                                                                                                          |

### Additional scripts

Beyond the standard lifecycle scripts, this connector includes specialized scripts:

| Script                                                                                                                | Purpose                                                                                                                                                                                                                                                                                                                                              |
| --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UniquenessCheck/uniquenessCheckAdChecksSql.ps1`, `UniquenessCheck/uniquenessCheckAdChecksSqlandAd.ps1`, and `UniquenessCheck/uniquenessCheckEntraIdChecksSqlandEntraId.ps1` | **Uniqueness validation scripts** - Validate proposed attribute values before provisioning against SQL + Active Directory and SQL + Microsoft Entra ID scenarios. Full configuration and usage details are documented in `UniquenessCheck/README.md`. |
| `SupportingFiles/createTableBlocklist.sql` and `SupportingFiles/importInitialDataFromCsv.ps1`                         | **Database helper files** - SQL table setup and optional initial CSV import tooling. Full setup and usage details are documented in `SupportingFiles/README.md`.                                                                                                                                                                                     |
| `GenerateUniqueData/example.create.ps1`                                                                               | **Legacy example script** - Demonstrates how to generate unique values by querying the SQL blocklist database in older PowerShell v1 connectors. While this is legacy code, it can be adapted for scenarios requiring custom unique value generation (e.g., employee numbers, random identifiers). Not required for standard V2 connector operation. |

For detailed configuration of the uniqueness validation scripts, see `UniquenessCheck/README.md`.

For database setup, table structure, and initial CSV import guidance, see `SupportingFiles/README.md`.

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/.
