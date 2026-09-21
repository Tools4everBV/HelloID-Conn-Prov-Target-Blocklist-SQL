# SupportingFiles

This folder contains helper files for preparing and maintaining the SQL blocklist database.

## Contents

| File                           | Purpose                                                                                      |
| ------------------------------ | -------------------------------------------------------------------------------------------- |
| `createTableBlocklist.sql`     | Creates the required SQL blocklist table and indexes.                                        |
| `importInitialDataFromCsv.ps1` | Imports initial blocklist data from CSV and enriches records using Active Directory lookups. |

## Database setup

Run `createTableBlocklist.sql` in SQL Server Management Studio (or equivalent) before using the connector.

### Table structure

| Column Name    | Data Type     | Description                                                                  |
| -------------- | ------------- | ---------------------------------------------------------------------------- |
| employeeId     | NVARCHAR(50)  | Unique identifier for a person (HelloID person).                             |
| attributeName  | NVARCHAR(50)  | Name of the attribute (for example Mail, SamAccountName, UserPrincipalName). |
| attributeValue | NVARCHAR(255) | Value of the attribute (for example john.doe@company.com).                   |
| whenCreated    | DATETIME2(7)  | Timestamp of original creation.                                              |
| whenUpdated    | DATETIME2(7)  | Timestamp of last update.                                                    |
| whenDeleted    | DATETIME2(7)  | Soft-delete timestamp; `NULL` for active records.                            |

### Indexes

The SQL script creates the following indexes to optimize lookups:

- `IX_blocklist` on `(attributeName, attributeValue)`
- `IX_blocklist_1` on `(attributeValue)`
- `IX_blocklist_2` filtered index on `(employeeId)` where employeeId is not null

## Initial CSV import

Use `importInitialDataFromCsv.ps1` to import historical values into the blocklist table.

### CSV format

Expected delimiter: `;`

Expected columns:

- `attributeName`
- `attributeValue`
- `employeeId`
- `whenCreated`
- `whenUpdated`
- `whenDeleted`

### What the script does

- Imports rows from CSV
- Looks up AD account details for mail entries
- Adds or updates blocklist entries in SQL
- Optionally adds `UserPrincipalName` entries based on mail lookup results
- Supports dry-run execution from the HelloID action context

> [!IMPORTANT]
> The script contains a placeholder action context line (`insert actioncontext in json format here`). Replace this with your real HelloID action context before execution.

> [!NOTE]
> For production use, validate AD module availability and permissions (`Get-ADUser`) in the runtime environment.
