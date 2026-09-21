# UniquenessCheck scripts

This folder contains scripts for uniqueness validation in external systems before creating or updating accounts.

## Available scripts

| Script                                          | Purpose                                                                                                                         |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `uniquenessCheckAdChecksSql.ps1`                | Uniqueness validation against the SQL blocklist. Designed for use in the HelloID built-in Active Directory connector.           |
| `uniquenessCheckAdChecksSqlAndAd.ps1`           | Combined uniqueness validation against both Active Directory and the SQL blocklist.                                             |
| `uniquenessCheckEntraIdChecksSqlandEntraId.ps1` | Combined uniqueness validation against both Microsoft Entra ID and the SQL blocklist. Includes Graph API checks and SQL checks. |

## How it works

The scripts validate proposed values (for example `mail`, `userPrincipalName`, `sAMAccountName`) before provisioning. They use retention period rules from the blocklist table:

- Value owned by another person and still within retention period: non-unique
- Value owned by another person and retention period expired: reusable
- Value owned by current person: unique or non-unique, depending on `allowSelfUsage`

The scripts return `NonUniqueFields` to HelloID so collisions are handled before provisioning errors occur.

### Script variants

- `uniquenessCheckAdChecksSql.ps1`: validates uniqueness using the SQL blocklist for Active Directory-driven scenarios.
- `uniquenessCheckAdChecksSqlAndAd.ps1`: validates against SQL and Active Directory.
- `uniquenessCheckEntraIdChecksSqlandEntraId.ps1`: validates against SQL and Microsoft Entra ID.

## Required configuration

> [!IMPORTANT]
> **Retention period synchronization**: use the same database connection and `retentionPeriod` configuration as the blocklist target connector. Keep retention values consistent across both components.

> [!WARNING]
> Configure the script before production use:
> 1. `correlationAttribute`
> 2. `allowSelfUsage`
> 3. `fieldsToCheck`

> [!IMPORTANT]
> The configured correlation field (typically `employeeId`) must be mapped in HelloID field mapping for all operations that use these checks (`create`, `update`, and others where applicable).

### Correlation attribute

```powershell
$correlationAttribute = [PSCustomObject]@{
	accountFieldName = "employeeId"  # Property name in the account object from HelloID
	systemFieldName  = "employeeId"  # Corresponding column name in the blocklist database
}
```

Used for:

- Ownership checks (current person vs another person)
- Self-usage behavior
- Restoring values for returning employees

### Allow self-usage

```powershell
$allowSelfUsage = $true
```

- `$true` (recommended): own existing values are considered unique
- `$false`: own values are treated as non-unique and must be regenerated

### Fields to check

```powershell
$fieldsToCheck = [PSCustomObject]@{
	"userPrincipalName" = [PSCustomObject]@{
		systemFieldName = 'userPrincipalName'
		accountValue    = $a.userPrincipalName
		keepInSyncWith  = @("mail", "proxyAddresses")
		crossCheckOn    = @("mail")
	}
	"mail" = [PSCustomObject]@{
		systemFieldName = 'mail'
		accountValue    = $a.mail
		keepInSyncWith  = @("userPrincipalName", "proxyAddresses")
		crossCheckOn    = @("userPrincipalName")
	}
}
```

Configuration fields:

- `systemFieldName`: `attributeName` value in the blocklist table
- `accountValue`: value from the HelloID account object
- `keepInSyncWith`: mark related fields as non-unique together
- `crossCheckOn`: check same value under additional attribute names

## Notes

- Script-specific mappings can differ between the three script variants.
- If a field is already marked non-unique, the scripts skip redundant checks for better performance.
- The SQL check logic escapes single quotes in values before building queries.
