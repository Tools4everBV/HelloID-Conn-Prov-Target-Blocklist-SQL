#########################################################################
# HelloID-Conn-Prov-Target-Blacklist-Check-On-External-Systems-AD-SQL
#########################################################################

# Initialize default properties
$a = $account | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json

# The entitlementContext contains the configuration
# - configuration: The configuration that is set in the Custom PowerShell configuration
$eRef = $entitlementContext | ConvertFrom-Json

$table = $eRef.configuration.table
$retentionPeriod = $eRef.configuration.retentionPeriod

# Operation is a script parameter which contains the action HelloID wants to perform for this entitlement
# It has one of the following values: "create", "enable", "update", "disable", "delete"
$o = $operation | ConvertFrom-Json

# Set Success to false at start, at the end, only when no error occurs it is set to true
$success = $false

# Initiate empty list for Non Unique Fields
$nonUniqueFields = [System.Collections.Generic.List[PSCustomObject]]::new()

#region Change mapping here

# Correlation Attribute
# Identifies and matches persons between the account object (from HelloID) and the blacklist database
# Used to determine ownership of values: does a blacklisted value belong to the current person or someone else?
# Required for: Self-usage checks, retention period validation, and ownership determination
#
# IMPORTANT: The accountFieldName specified here MUST be mapped in your field mapping configuration
# for ALL operations where this uniqueness check is used (create, update, etc.).
# If this field is not mapped or is empty, the uniqueness check cannot function correctly.
# Common mistake: Mapping the field only for 'create' but using the uniqueness check for both 'create' and 'update'.
# Solution: Ensure this field is mapped for all relevant operations in your HelloID configuration.
$correlationAttribute = [PSCustomObject]@{
    accountFieldName = "employeeId"  # Property name in the account object received from HelloID - MUST be mapped in field mapping!
    systemFieldName  = "employeeId"  # Corresponding column name in the blacklist database table
}

# Allow Self-Usage Configuration
# Determines whether a person can reuse values they already own in the blacklist database
# - $true (recommended): Person's own values are treated as unique
# Example: Person can keep their existing email address without triggering non-unique warnings
# This is the normal behavior for most scenarios
# - $false (strict mode): Person's own values are also treated as non-unique
# Example: Forces regeneration of all values, even if the person already owns them
# Use case: When implementing a complete value refresh or migration scenario
# Note: Works in conjunction with $correlationAttribute to determine value ownership
$allowSelfUsage = $true

# Fields to Check for Uniqueness
# Defines which account properties should be validated against the blacklist database
# Each field configuration includes:
# - systemFieldName: The database column name to query (attributeName field in the blacklist table)
# - accountValue: The actual value from the account object to validate
# - keepInSyncWith: Related properties that share uniqueness status (if one is non-unique, all are marked non-unique)
# - crossCheckOn: Additional properties to check for conflicts (searches across multiple attributeName values)
# Example: If userPrincipalName="user@domain.com", also check if mail="user@domain.com" exists
$fieldsToCheck = [PSCustomObject]@{
    "userPrincipalName" = [PSCustomObject]@{
        systemFieldName = 'userPrincipalName'
        accountValue    = $a.userPrincipalName
        keepInSyncWith  = @("mail", "proxyAddresses")
        crossCheckOn    = @("mail")
    }
    "mail"              = [PSCustomObject]@{
        systemFieldName = 'mail'
        accountValue    = $a.mail
        keepInSyncWith  = @("userPrincipalName", "proxyAddresses")
        crossCheckOn    = @("userPrincipalName")
    }
    "proxyAddresses"    = [PSCustomObject]@{
        systemFieldName = 'mail' # Note: proxyAddresses normally isn't in the blacklist database, only the primary SMTP address (mail attribute) is checked
        accountValue    = $a.proxyAddresses
        keepInSyncWith  = @("userPrincipalName", "mail")
        crossCheckOn    = @("userPrincipalName")
    }
    "sAMAccountName"    = [PSCustomObject]@{
        systemFieldName = 'sAMAccountName'
        accountValue    = $a.sAMAccountName
        keepInSyncWith  = @("commonName")
        crossCheckOn    = $null
    }
    "commonName"        = [PSCustomObject]@{
        systemFieldName = 'cn'
        accountValue    = $a.commonName
        keepInSyncWith  = $null
        crossCheckOn    = $null
    }
}
#endregion Change mapping here

#region functions
function Invoke-SQLQuery {
    param(
        [parameter(Mandatory = $true)]
        $ConnectionString,

        [parameter(Mandatory = $false)]
        $Username,

        [parameter(Mandatory = $false)]
        $Password,

        [parameter(Mandatory = $true)]
        $SqlQuery,

        [parameter(Mandatory = $true)]
        [ref]$Data
    )
    try {
        $Data.value = $null

        # Initialize connection and execute query
        if (-not[String]::IsNullOrEmpty($Username) -and -not[String]::IsNullOrEmpty($Password)) {
            # First create the PSCredential object
            $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $credential = [System.Management.Automation.PSCredential]::new($Username, $securePassword)

            # Set the password as read only
            $credential.Password.MakeReadOnly()

            # Create the SqlCredential object
            $sqlCredential = [System.Data.SqlClient.SqlCredential]::new($credential.username, $credential.password)
        }
        # Connect to the SQL server
        $SqlConnection = [System.Data.SqlClient.SqlConnection]::new()
        $SqlConnection.ConnectionString = $ConnectionString
        if (-not[String]::IsNullOrEmpty($sqlCredential)) {
            $SqlConnection.Credential = $sqlCredential
        }
        $SqlConnection.Open()
        Write-Verbose "Successfully connected to SQL database"

        # Set the query
        $SqlCmd = [System.Data.SqlClient.SqlCommand]::new()
        $SqlCmd.Connection = $SqlConnection
        $SqlCmd.CommandText = $SqlQuery

        # Set the data adapter
        $SqlAdapter = [System.Data.SqlClient.SqlDataAdapter]::new()
        $SqlAdapter.SelectCommand = $SqlCmd

        # Set the output with returned data
        $DataSet = [System.Data.DataSet]::new()
        $null = $SqlAdapter.Fill($DataSet)

        # Set the output with returned data
        $Data.value = $DataSet.Tables[0] | Select-Object -Property * -ExcludeProperty RowError, RowState, Table, ItemArray, HasErrors
    }
    catch {
        $Data.Value = $null
        throw $_
    }
    finally {
        if ($SqlConnection.State -eq "Open") {
            $SqlConnection.close()
            Write-Verbose "Successfully disconnected from SQL database"
        }
    }
}
#endregion functions

try {
    # Validate that correlation attribute is mapped and has a value
    if ([string]::IsNullOrEmpty($correlationAttribute.accountFieldName)) {
        throw "Correlation attribute 'accountFieldName' is not configured. This is a mandatory configuration setting."
    }

    if (-not ($a.PSObject.Properties.Name -contains $correlationAttribute.accountFieldName)) {
        throw "Correlation attribute [$($correlationAttribute.accountFieldName)] is not present in the account object. Please ensure this field is mapped in your HelloID field mapping configuration for all operations (create, update, etc.) where this uniqueness check is used."
    }

    if ([string]::IsNullOrEmpty($a.($correlationAttribute.accountFieldName))) {
        throw "Correlation attribute [$($correlationAttribute.accountFieldName)] exists in the account object but has no value. Please ensure this field is properly mapped with a valid value in your HelloID field mapping configuration."
    }

    Write-Information "Correlation attribute validation successful: [$($correlationAttribute.accountFieldName)] = [$($a.($correlationAttribute.accountFieldName))]"

    # Query current data in database
    foreach ($fieldToCheck in $fieldsToCheck.PsObject.Properties | Where-Object { -not[String]::IsNullOrEmpty($_.Value.accountValue) }) {
    
        # Skip if this field is already marked as non-unique
        if ($nonUniqueFields -contains $fieldToCheck.Name) {
            Write-Verbose "Skipping uniqueness check for property [$($fieldToCheck.Name)] with value(s) [$($fieldToCheck.Value.accountValue -join ', ')] because it is already marked as non-unique (either directly or through keepInSyncWith configuration)."
            continue
        }

        foreach ($fieldToCheckAccountValue in $fieldToCheck.Value.accountValue) {
            # Remove smtp: prefix for proxyAddresses
            $fieldToCheckAccountValue = $fieldToCheckAccountValue -replace '(?i)^smtp:', ''

            $sqlAccountValue = $fieldToCheckAccountValue.Replace("'", "''")
        
            # Build WHERE clause starting with the primary field
            $whereClause = "[attributeName] = '$($fieldToCheck.Value.systemFieldName)' AND [attributeValue] = '$sqlAccountValue'"
        
            # Add cross-check conditions if configured
            if (@($fieldToCheck.Value.crossCheckOn).Count -ge 1) {
                foreach ($fieldToCrossCheckOn in $fieldToCheck.Value.crossCheckOn) {
                    # Get the system field name for the cross-check field
                    $crossCheckSystemFieldName = $fieldsToCheck.$fieldToCrossCheckOn.systemFieldName
                
                    # Custom check for proxyAddresses to prefix value with 'smtp:'
                    if ($fieldToCrossCheckOn -eq 'proxyAddresses') {
                        $whereClause = $whereClause + " OR ([attributeName] = '$crossCheckSystemFieldName' AND [attributeValue] = 'smtp:$sqlAccountValue')"
                    }
                    else {
                        $whereClause = $whereClause + " OR ([attributeName] = '$crossCheckSystemFieldName' AND [attributeValue] = '$sqlAccountValue')"
                    }
                }
            }
        
            $querySelect = "SELECT * FROM [$table] WHERE $whereClause"

            $querySelectSplatParams = @{
                ConnectionString = $eRef.configuration.connectionString
                Username         = $eRef.configuration.username
                Password         = $eRef.configuration.password
                SqlQuery         = $querySelect
                ErrorAction      = "Stop"
            }

            $querySelectResult = [System.Collections.ArrayList]::new()
            Invoke-SQLQuery @querySelectSplatParams -Data ([ref]$querySelectResult)
            $selectRowCount = ($querySelectResult | measure-object).count
            Write-Verbose "Queried data from table [$table] for attribute [$($fieldToCheck.Name)] with cross-check. Query: $($querySelect). Returned rows: $selectRowCount"

            # Check property uniqueness with retention period logic
            if ($selectRowCount -gt 0) {
                foreach ($dbRow in $querySelectResult) {
                    # Check if the person is using the value themselves (based on correlation attribute)
                    if ($dbRow.($correlationAttribute.systemFieldName) -eq $a.($correlationAttribute.accountFieldName)) {
                        if ($allowSelfUsage) {
                            Write-Information "Person is using property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] themselves in SQL blacklist. Continuing with AD availability check."
                        }
                        else {
                            # Self-usage is not allowed - treat as non-unique
                            Write-Warning "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is not unique. Person is using this value themselves, but self-usage is disabled (allowSelfUsage = false). [$($correlationAttribute.systemFieldName)]: [$($dbRow.($correlationAttribute.systemFieldName))]."
                            [void]$NonUniqueFields.Add($fieldToCheck.Name)
                        
                            # Add related fields from keepInSyncWith
                            if (@($fieldToCheck.Value.keepInSyncWith).Count -ge 1) {
                                foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $a.PsObject.Properties.Name }) {
                                    Write-Warning "Property [$fieldToKeepInSyncWith] is marked as non-unique because it is configured to keepInSyncWith [$($fieldToCheck.Name)], which is not unique."
                                    [void]$NonUniqueFields.Add($fieldToKeepInSyncWith)
                                }
                            }
                        
                            # Break out of the loop as we only need to find one non-unique field
                            break
                        }
                    }
                    else {
                        # Check retention period if whenDeleted is set
                        if (-NOT [string]::IsNullOrEmpty($dbRow.whenDeleted)) {
                            $whenDeletedDate = [datetime]($dbRow.whenDeleted)
                            $daysDiff = (New-TimeSpan -Start $whenDeletedDate -End (Get-Date)).Days
                        }
                        else {
                            $daysDiff = 0
                        }

                        if ($daysDiff -lt $retentionPeriod) {
                            # Check if this is a direct match or cross-check match
                            if ($dbRow.attributeName -eq $fieldToCheck.Value.systemFieldName) {
                                Write-Warning "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is not unique. It is currently in use by [$($correlationAttribute.systemFieldName)]: [$($dbRow.($correlationAttribute.systemFieldName))]. The associated [whenDeleted] timestamp [$($dbRow.whenDeleted)] is still within the allowed retention period of [$($retentionPeriod) days]."
                            }
                            else {
                                Write-Warning "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is not unique due to cross-check. The value exists as [$($dbRow.attributeName)] = [$($dbRow.attributeValue)] in use by [$($correlationAttribute.systemFieldName)]: [$($dbRow.($correlationAttribute.systemFieldName))]. The associated [whenDeleted] timestamp [$($dbRow.whenDeleted)] is still within the allowed retention period of [$($retentionPeriod) days]."
                            }
                            [void]$NonUniqueFields.Add($fieldToCheck.Name)
                            
                            # Add related fields from keepInSyncWith
                            if (@($fieldToCheck.Value.keepInSyncWith).Count -ge 1) {
                                foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $a.PsObject.Properties.Name }) {
                                    Write-Warning "Property [$fieldToKeepInSyncWith] is marked as non-unique because it is configured to keepInSyncWith [$($fieldToCheck.Name)], which is not unique."
                                    [void]$NonUniqueFields.Add($fieldToKeepInSyncWith)
                                }
                            }
                            
                            # Break out of the loop as we only need to find one non-unique field
                            break
                        }
                        else {
                            Write-Information "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is reusable based on SQL retention. Although it was previously used by [$($correlationAttribute.systemFieldName)]: [$($dbRow.($correlationAttribute.systemFieldName))], the [whenDeleted] timestamp [$($dbRow.whenDeleted)] exceeds the allowed retention period of [$($retentionPeriod) days]. Continuing with AD availability check for final uniqueness verdict."
                        }
                    }
                }
            }
            elseif ($selectRowCount -eq 0) {
                Write-Information "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] was not found in SQL blacklist. Continuing with AD availability check for final uniqueness verdict."
            }

            # If SQL already marked this field as non-unique, skip AD check
            if ($nonUniqueFields -contains $fieldToCheck.Name) {
                continue
            }

            # Check if the value is available in AD (same behavior as built-in AD uniqueness check)
            $adFilter = $null
            $adSystemFieldName = $fieldToCheck.Value.systemFieldName

            $adAccountValue = $fieldToCheckAccountValue.Replace("'", "''")

            if ($adSystemFieldName -eq 'proxyAddresses') {
                # proxyAddresses is multi-valued and normally stored with smtp:/SMTP: prefix in AD
                $adFilter = "$adSystemFieldName -eq 'smtp:$adAccountValue'"
            }
            else {
                $adFilter = "$adSystemFieldName -eq '$adAccountValue'"
            }

            if (@($fieldToCheck.Value.crossCheckOn).Count -ge 1) {
                foreach ($fieldToCrossCheckOn in $fieldToCheck.Value.crossCheckOn) {
                    $crossCheckAdSystemFieldName = $fieldsToCheck.$fieldToCrossCheckOn.systemFieldName
                    if ($crossCheckAdSystemFieldName -eq 'proxyAddresses') {
                        $adFilter = $adFilter + " -or $crossCheckAdSystemFieldName -eq 'smtp:$adAccountValue'"
                    }
                    else {
                        $adFilter = $adFilter + " -or $crossCheckAdSystemFieldName -eq '$adAccountValue'"
                    }
                }
            }

            $actionMessage = "querying AD account where [filter] = [$adFilter]"
            $getADAccountSplatParams = @{
                Filter      = $adFilter
                Verbose     = $false
                ErrorAction = "Stop"
            }
            $getADAccountResponse = Get-ADUser @getADAccountSplatParams
            $correlatedAdAccounts = @($getADAccountResponse)

            Write-Information "Queried AD account where [filter] = [$adFilter]. Result count: [$($correlatedAdAccounts.Count)]"

            if ($correlatedAdAccounts.Count -gt 0) {
                $currentAdAccount = $null

                if ($o.ToLower() -ne "create" -and -not [string]::IsNullOrEmpty($aRef.ObjectGuid)) {
                    $currentAdAccount = @($correlatedAdAccounts | Where-Object { [string]$_.ObjectGuid -eq [string]$aRef.ObjectGuid } | Select-Object -First 1)
                }

                if ($currentAdAccount) {
                    if ($allowSelfUsage) {
                        Write-Information "Person is using property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] themselves in AD."
                    }
                    else {
                        Write-Warning "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is not unique. Person is using this value themselves in AD, but self-usage is disabled (allowSelfUsage = false)."
                        [void]$NonUniqueFields.Add($fieldToCheck.Name)

                        if (@($fieldToCheck.Value.keepInSyncWith).Count -ge 1) {
                            foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $a.PsObject.Properties.Name }) {
                                Write-Warning "Property [$fieldToKeepInSyncWith] is marked as non-unique because it is configured to keepInSyncWith [$($fieldToCheck.Name)], which is not unique."
                                [void]$NonUniqueFields.Add($fieldToKeepInSyncWith)
                            }
                        }

                        break
                    }
                }
                else {
                    Write-Warning "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is not unique because this value already exists in AD."
                    [void]$NonUniqueFields.Add($fieldToCheck.Name)

                    if (@($fieldToCheck.Value.keepInSyncWith).Count -ge 1) {
                        foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $a.PsObject.Properties.Name }) {
                            Write-Warning "Property [$fieldToKeepInSyncWith] is marked as non-unique because it is configured to keepInSyncWith [$($fieldToCheck.Name)], which is not unique."
                            [void]$NonUniqueFields.Add($fieldToKeepInSyncWith)
                        }
                    }

                    break
                }
            }
            else {
                Write-Information "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is unique across SQL blacklist and AD."
            }
        }
    }
}
catch {
    $ex = $PSItem

    $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
    $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

    Write-Warning $warningMessage

    # Required to write an error as uniqueness check doesn't show auditlog
    Write-Error $auditMessage
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-not($auditLogs.IsError -contains $true)) {
        $success = $true
    }

    $nonUniqueFields = @($nonUniqueFields | Sort-Object -Unique)

    # Send results
    $result = [PSCustomObject]@{
        Success         = $success
        NonUniqueFields = $nonUniqueFields
    }

    Write-Output ($result | ConvertTo-Json -Depth 10)
}
