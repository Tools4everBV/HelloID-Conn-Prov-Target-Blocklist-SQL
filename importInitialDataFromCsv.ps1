#####################################################
# Blacklist CSV Import with AD Lookup
# CSV format: attributeName, attributeValue, employeeId, whenCreated, whenUpdated, whenDeleted
# Imports blacklist entries and enriches with AD lookup for missing employee IDs
#####################################################

# Parameters
param(
    [string]$CsvPath = 'C:\HelloID\Blacklist-initial-import\blacklist_export_final.csv',
    [string]$MailAttribute = 'mail',
    [int]$BatchSize = 50
)

# Get configuration from HelloID actionContext
#$actionContext = $('insert actioncontext in json format here' | ConvertFrom-Json)
$actionContext = $('{ "Configuration": { "connectionString": "Server=szb-helloid-sqldb-01.privatelink.database.windows.net;Database=HelloID;", "password": "2nykfiC=FVskSp", "table": "blacklist", "username": "HelloID_usr" }, "DryRun": false, "Operation": "undefined", "Data": { "employeeId": "4035584", "Mail": "a.witzel@zorgbalans.nl", "UserPrincipalName": "a.witzel@zorgbalans.nl" }, "CorrelationConfiguration": { "Enabled": false, "PersonField": "Person.ExternalId", "PersonFieldValue": null, "AccountField": "employeeId", "AccountFieldValue": null }, "AccountCorrelated": false, "References": { "Account": null, "ManagerAccount": null }, "Origin": "enforcement" }' | ConvertFrom-Json)

# Validate parameters
if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found at: $CsvPath"
    exit 1
}

$csvImport = @(Import-Csv -Path $CsvPath -Delimiter ';')

# Debug: Check if CSV is loaded
Write-Warning "CSV file loaded: $(($csvImport | Measure-Object).Count) rows found"
if ($csvImport.Count -eq 0) {
    Write-Warning "ERROR: CSV file is empty or not found at path: C:\HelloID\Blacklist-initial-import\blacklist_export_final.csv"
    exit
}

# Show actual CSV column names
if ($csvImport.Count -gt 0) {
    $actualColumns = $csvImport[0].PSObject.Properties.Name
    Write-Warning "Actual CSV columns: $($actualColumns -join ', ')"
}

# Extract configuration
$connectionString = $actionContext.Configuration.connectionString
$username = $actionContext.Configuration.username
$password = $actionContext.Configuration.password
$table = $actionContext.Configuration.table
$dryRun = $actionContext.DryRun

# AD Configuration
$adConfig = @{
    employeeIdAttribute = $actionContext.CorrelationConfiguration.AccountField
}

# Global counters
$script:stats = @{
    Created      = 0
    Updated      = 0
    Errors       = 0
    TotalRows    = $csvImport.Count
    StartTime    = Get-Date
}

#region SQL Connection Management
$script:sqlConnection = $null

function Get-SqlConnection {
    if ($script:sqlConnection -eq $null -or $script:sqlConnection.State -ne "Open") {
        if (-not[String]::IsNullOrEmpty($username) -and -not[String]::IsNullOrEmpty($password)) {
            $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
            $credential = [System.Management.Automation.PSCredential]::new($username, $securePassword)
            $credential.Password.MakeReadOnly()
            $script:sqlCredential = [System.Data.SqlClient.SqlCredential]::new($credential.username, $credential.password)
        }

        $script:sqlConnection = [System.Data.SqlClient.SqlConnection]::new()
        $script:sqlConnection.ConnectionString = $connectionString
        if ($script:sqlCredential) {
            $script:sqlConnection.Credential = $script:sqlCredential
        }
        $script:sqlConnection.Open()
        Write-Verbose "SQL Connection established"
    }
    return $script:sqlConnection
}

function Close-SqlConnection {
    if ($script:sqlConnection -and $script:sqlConnection.State -eq "Open") {
        $script:sqlConnection.Close()
        Write-Verbose "SQL Connection closed"
    }
}
#endregion

#region functions
function Invoke-SQLQueryParameterized {
    param(
        [parameter(Mandatory = $true)]
        [string]$SqlQuery,
        
        [parameter(Mandatory = $false)]
        [hashtable]$Parameters,
        
        [parameter(Mandatory = $true)]
        [ref]$Data
    )
    try {
        $Data.value = $null
        $SqlConnection = Get-SqlConnection
        
        $SqlCmd = [System.Data.SqlClient.SqlCommand]::new()
        $SqlCmd.Connection = $SqlConnection
        $SqlCmd.CommandText = $SqlQuery

        # Add parameters
        if ($Parameters) {
            foreach ($key in $Parameters.Keys) {
                $null = $SqlCmd.Parameters.AddWithValue("@$key", $Parameters[$key])
            }
        }

        $SqlAdapter = [System.Data.SqlClient.SqlDataAdapter]::new()
        $SqlAdapter.SelectCommand = $SqlCmd

        $DataSet = [System.Data.DataSet]::new()
        $null = $SqlAdapter.Fill($DataSet)

        # Return the DataTable directly to preserve Rows property
        $Data.value = $DataSet.Tables[0]
    }
    catch {
        $Data.Value = $null
        throw $_
    }
}

function Get-ADUserByAttribute {
    param(
        [string]$Attribute,
        [string]$Value
    )
    
    try {
        $filter = "$Attribute -eq '$Value'"
        $adUser = Get-ADUser -Filter $filter -Properties $adConfig.employeeIdAttribute, UserPrincipalName -ErrorAction Stop
        return $adUser
    }
    catch {
        Write-Verbose "AD lookup failed for $Attribute='$Value': $($_.Exception.Message)"
        return $null
    }
}

function Add-BlacklistEntry {
    param(
        [string]$AttributeName,
        [string]$AttributeValue,
        [string]$EmployeeId,
        [bool]$IsUpdate,
        [string]$AdStatus
    )
    
    $nowDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fff"
    
    try {
        if ($IsUpdate) {
            # Update existing entry
            if ($EmployeeId) {
                $sqlQuery = "UPDATE [$table] SET [employeeId] = @employeeId, [whenUpdated] = @whenUpdated, [whenDeleted] = null WHERE [attributeName] = @attributeName AND [attributeValue] = @attributeValue"
            } else {
                $sqlQuery = "UPDATE [$table] SET [whenUpdated] = @whenUpdated, [whenDeleted] = @whenUpdated WHERE [attributeName] = @attributeName AND [attributeValue] = @attributeValue"
            }
            
            $params = @{
                attributeName  = $AttributeName
                attributeValue = $AttributeValue
                whenUpdated    = $nowDate
            }
            if ($EmployeeId) {
                $params['employeeId'] = $EmployeeId
            }
            
            if (-not $dryRun) {
                $data = $null
                Invoke-SQLQueryParameterized -SqlQuery $sqlQuery -Parameters $params -Data ([ref]$data) -ErrorAction Stop
                Write-Warning "Updated entry: [$AttributeName] = [$AttributeValue] ($AdStatus)"
                $script:stats.Updated++
            } else {
                Write-Warning "DryRun: Would update entry: [$AttributeName] = [$AttributeValue] ($AdStatus)"
                $script:stats.Updated++
            }
        } else {
            # Insert new entry
            $sqlQuery = @"
INSERT INTO [$table] 
([attributeName], [attributeValue], [employeeId], [whenCreated], [whenUpdated], [whenDeleted])
VALUES 
(@attributeName, @attributeValue, @employeeId, @whenCreated, @whenUpdated, @whenDeleted)
"@
            
            $params = @{
                attributeName  = $AttributeName
                attributeValue = $AttributeValue
                employeeId     = $EmployeeId
                whenCreated    = $nowDate
                whenUpdated    = $nowDate
                whenDeleted    = $nowDate
            }
            
            if (-not $dryRun) {
                $data = $null
                Invoke-SQLQueryParameterized -SqlQuery $sqlQuery -Parameters $params -Data ([ref]$data) -ErrorAction Stop
                Write-Warning "Created entry: [$AttributeName] = [$AttributeValue] ($AdStatus)"
                $script:stats.Created++
            } else {
                Write-Warning "DryRun: Would create entry: [$AttributeName] = [$AttributeValue] ($AdStatus)"
                $script:stats.Created++
            }
        }
    }
    catch {
        throw $_
    }
}

function Test-BlacklistEntryExists {
    param(
        [string]$AttributeName,
        [string]$AttributeValue
    )
    
    $sqlQuery = "SELECT TOP 1 employeeId FROM [$table] WHERE [attributeName] = @attributeName AND [attributeValue] = @attributeValue"
    $params = @{
        attributeName  = $AttributeName
        attributeValue = $AttributeValue
    }
    
    $data = $null
    Invoke-SQLQueryParameterized -SqlQuery $sqlQuery -Parameters $params -Data ([ref]$data) -ErrorAction Stop
    
    # Check if DataTable has rows
    return ($null -ne $data -and $data.Rows.Count -gt 0)
}
#endregion functions

try {
    $startTime = Get-Date
    
    Write-Warning "Starting blacklist import (DryRun: $dryRun)"
    Write-Warning "=========================================="
    Write-Warning "Configuration:"
    Write-Warning "  CSV Path: $CsvPath"
    Write-Warning "  Table: $table"
    Write-Warning "  Employee ID Attribute: $($adConfig.employeeIdAttribute)"
    Write-Warning "  Mail Attribute: $MailAttribute"
    Write-Warning "  CSV Rows: $($csvImport.Count)"
    Write-Warning "  Batch Size: $BatchSize"
    Write-Warning "=========================================="
    
    foreach ($row in $csvImport) {
        try {
            $attributeName = $row.attributeName
            $attributeValue = $row.attributeValue
            $currentEmployeeId = $row.employeeId
            
            # Skip if attribute value is empty
            if ([string]::IsNullOrEmpty($attributeValue)) {
                Write-Verbose "Skipping empty attributeValue"
                continue
            }
            
            Write-Verbose "Processing: [$attributeName] = [$attributeValue]"
            
            # Lookup in AD for employee ID and UPN (if mail attribute)
            $employeeIdFromAD = $null
            $upnFromAD = $null
            $adStatus = "Account not found in AD"
            
            if ($attributeName -eq $MailAttribute) {
                Write-Verbose "Looking up $MailAttribute in AD to get employeeId and UPN..."
                $adUser = Get-ADUserByAttribute -Attribute $MailAttribute -Value $attributeValue
                
                if ($adUser) {
                    # Account found - use UPN from AD
                    $employeeIdFromAD = $adUser.($adConfig.employeeIdAttribute)
                    $upnFromAD = $adUser.UserPrincipalName
                    
                    if ($employeeIdFromAD) {
                        $adStatus = "EmployeeId: $employeeIdFromAD"
                    } else {
                        $adStatus = "Account found but has no employeeId"
                    }
                    
                    Write-Verbose "Found in AD - $adStatus, UPN: $upnFromAD"
                } else {
                    # Account not found - use mail as fallback UPN
                    $upnFromAD = $attributeValue
                    Write-Verbose "Account not found in AD - using mail as UPN: $upnFromAD"
                }
            }
            
            # Check if entry exists
            $entryExists = Test-BlacklistEntryExists -AttributeName $attributeName -AttributeValue $attributeValue
            
            # Add or update entry
            Add-BlacklistEntry -AttributeName $attributeName -AttributeValue $attributeValue `
                -EmployeeId $employeeIdFromAD -IsUpdate $entryExists -AdStatus $adStatus
            
            # Step 2: If mail attribute and UPN found -> also add UPN to blacklist
            if ($attributeName -eq $MailAttribute -and -not [string]::IsNullOrEmpty($upnFromAD)) {
                Write-Verbose "Processing UPN entry [$upnFromAD] from mail [$attributeValue]"
                
                $upnExists = Test-BlacklistEntryExists -AttributeName 'UserPrincipalName' -AttributeValue $upnFromAD
                
                $upnStatus = if ($employeeIdFromAD) { "EmployeeId: $employeeIdFromAD" } else { "No employeeId" }
                Add-BlacklistEntry -AttributeName 'UserPrincipalName' -AttributeValue $upnFromAD `
                    -EmployeeId $employeeIdFromAD -IsUpdate $upnExists -AdStatus $upnStatus
            }
        }
        catch {
            Write-Warning "Error processing row with attributeName [$($row.attributeName)] = [$($row.attributeValue)]. Error: $($_.Exception.Message)"
            $script:stats.Errors++
        }
    }
    
    $elapsedTime = (Get-Date) - $startTime
    
    Write-Warning "`n=========================================="
    Write-Warning "Import Summary"
    Write-Warning "=========================================="
    Write-Warning "Created:      $($script:stats.Created)"
    Write-Warning "Updated:      $($script:stats.Updated)"
    Write-Warning "Errors:       $($script:stats.Errors)"
    Write-Warning "Total:        $($script:stats.Created + $script:stats.Updated + $script:stats.Errors)"
    Write-Warning "Elapsed Time: $($elapsedTime.TotalSeconds)s"
    Write-Warning "=========================================="
}
catch {
    $ex = $PSItem
    Write-Warning "FATAL ERROR: $($ex.Exception.Message)"
    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line)"
}
finally {
    Close-SqlConnection
}