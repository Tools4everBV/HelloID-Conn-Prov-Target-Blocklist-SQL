#####################################################
# HelloID-Conn-Prov-Target-Blocklist-Create-SQL-Unique
#
#####################################################
# Initialize default values

$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false # Set to false at start, at the end, only when no error occurs it is set to true
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# Used to connect to SQL server.
$connectionString = $c.connectionString
$username = $c.username
$password = $c.password
$table = $c.table

#region Change mapping here
# Define prefix of generated unique value
$prefix = $p.Name.FamilyName.substring(0, 1)
$suffix = ""
# Define range of allowed numbers
$inputRange = 0000..9999
# Define amount of characters the string should always be. E.g. 4 if the string should always be 4 chars long, even if the generated number is 3, the string will be "0003"
$amountOfChars = 4 # If left empty, the generated number will not be prefixed by leading zeros

$account = [PSCustomObject]@{
    "SamAccountName" = "Unknown" # Generated further down in script
}
#endregion Change mapping here

# Define aRef
$aRef = $account.SamAccountName # Use most unique propertie, e.g. SamAccountName or UserPrincipalName

# Define account properties to store in account data
$storeAccountFields = @("SamAccountName")

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
        $SqlConnection.ConnectionString = "$ConnectionString"
        if (-not[String]::IsNullOrEmpty($sqlCredential)) {
            $SqlConnection.Credential = $sqlCredential
        }
        $SqlConnection.Open()
        Write-Information "Successfully connected to SQL database" 

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
            Write-Information "Successfully disconnected from SQL database"
        }
    }
}
#endregion functions

try {
    # Query current data in database
    try {
        # Enclose Property Names with brackets []
        $querySelectProperties = $("[" + ($account.PSObject.Properties.Name -join "],[") + "]")
        $querySelect = "
        SELECT
            $($querySelectProperties)
        FROM
            $table"

        Write-Information "Querying data from table [$($table)]. Query: $($querySelect)"

        $querySelectSplatParams = @{
            ConnectionString = $connectionString
            Username         = $username
            Password         = $password
            SqlQuery         = $querySelect
            ErrorAction      = "Stop"
        }
        $querySelectResult = [System.Collections.ArrayList]::new()
        Invoke-SQLQuery @querySelectSplatParams -Data ([ref]$querySelectResult)

        Write-Information "Successfully queried data from table [$($table)]. Query: $($querySelect). Returned rows: $(($querySelectResult | Measure-Object).Count)"
    }
    catch {
        $ex = $PSItem
        # Set Verbose error message
        $verboseErrorMessage = $ex.Exception.Message
        # Set Audit error message
        $auditErrorMessage = $ex.Exception.Message

        Write-Information "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
        $auditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Error querying data from table [$($table)]. Query: $($querySelect). Error Message: $($auditErrorMessage)"
                IsError = $True
            })

        # Skip further actions, as this is a critical error
        continue
    }

    # Get current values and generate random value that does not exist yet
    try {
        # Format input range to specified amount of chars, prefix and/or suffix
        $inputRange = $inputRange | ForEach-Object { "$prefix{0:d$amountOfChars}$suffix" -f $_ }

        Write-Information "Generating random value between [$($inputRange[0])] and [$($inputRange[-1])] that doesn't exist in blocklist"

        $currentValues = $querySelectResult."$($column)" | Sort-Object
        $excludeRange = $currentValues

        $regexExcludeRange = '(?i)^(' + (($excludeRange | Foreach-Object { [regex]::escape($_) }) -join “|”) + ')$'
        $randomRange = $inputRange -notmatch $regexExcludeRange
        if ($null -eq $randomRange) {
            throw "Error generating random value: No more values allowed. Please adjust the range. Current range: $($inputRange | Select-Object -First 1) to $($inputRange | Select-Object -Last 1)"
        }
        $uniqueValue = Get-Random -InputObject $randomRange

        # Set SamAccountName of Account object with generated unique value
        $account.SamAccountName = $uniqueValue

        Write-Information "Successfully generated random value between [$($inputRange[0])] and [$($inputRange[-1])] that doesn't exist in blocklist: [$($uniqueValue)]"
    }
    catch {
        $ex = $PSItem
        # Set Verbose error message
        $verboseErrorMessage = $ex.Exception.Message
        # Set Audit error message
        $auditErrorMessage = $ex.Exception.Message

        Write-Information "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
        $auditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Error generating random value between [$($inputRange[0])] and [$($inputRange[-1])] that doesn't exist in blocklist. Error Message: $auditErrorMessage"
                IsError = $True
            })

        # Skip further actions, as this is a critical error
        continue
    }

    # Update blocklist database
    try {
        # Enclose Property Names with brackets []
        $queryInsertProperties = $("[" + ($account.PSObject.Properties.Name -join "],[") + "]")
        # Enclose Property Values with single quotes ''
        $queryInsertValues = $("'" + ($account.PSObject.Properties.Value -join "','") + "'")

        $queryInsert = "
        INSERT INTO $table
            ($($queryInsertProperties))
        VALUES
            ($($queryInsertValues))"

        if (-not($dryRun -eq $true)) {
            Write-Information "Inserting data into table [$($table)]. Query: $($queryInsert)"

            $queryInsertSplatParams = @{
                ConnectionString = $connectionString
                Username         = $username
                Password         = $password
                SqlQuery         = $queryInsert
                ErrorAction      = "Stop"
            }

            $queryInsertResult = [System.Collections.ArrayList]::new()
            Invoke-SQLQuery @queryInsertSplatParams -Data ([ref]$queryInsertResult)

            $auditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Successfully inserted data into table [$($table)]. Query: $($queryInsert)"
                    IsError = $false;
                });   
        }
        else {
            Write-Warning "DryRun: Would insert data into table [$($table)]. Query: $($queryInsert)"
        }
    }
    catch {
        $ex = $PSItem
        # Set Verbose error message
        $verboseErrorMessage = $ex.Exception.Message
        # Set Audit error message
        $auditErrorMessage = $ex.Exception.Message

        Write-Information "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
        $auditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Error inserting data into table [$($table)]. Query: $($queryInsert). Error Message: $($auditErrorMessage)"
                IsError = $True
            })
    }

    # Define ExportData with account fields and correlation property 
    $exportData = $account.PsObject.Copy() | Select-Object $storeAccountFields
    # Add aRef to exportdata
    $exportData | Add-Member -MemberType NoteProperty -Name "AccountReference" -Value $aRef -Force
}
catch {
    $ex = $PSItem
    # Set Verbose error message
    $verboseErrorMessage = $ex.Exception.Message
    # Set Audit error message
    $auditErrorMessage = $ex.Exception.Message

    Write-Information "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
    $auditLogs.Add([PSCustomObject]@{
            # Action  = "" # Optional
            Message = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
            IsError = $True
        })
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($auditLogs.IsError -contains $true)) {
        $success = $true
    }

    # Send results
    $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $aRef
        AuditLogs        = $auditLogs
        Account          = $account

        # Optionally return data for use in other systems
        ExportData       = $exportData
    }

    Write-Output ($result | ConvertTo-Json -Depth 10)
}