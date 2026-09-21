#####################################################
# HelloID-Conn-Prov-Target-Blocklist-SQL-Create
# Use data from dependent system
#####################################################

$table = $actionContext.configuration.table
$retentionPeriod = $actionContext.configuration.retentionPeriod

$attributeNames = $($actionContext.Data | Select-Object * -ExcludeProperty employeeId, whenDeleted, whenCreated, whenUpdated).PSObject.Properties.Name

# Set AccountReference to employeeId at the top level, since it's always the current person's employeeId — no need to set it within a specific action
$outputContext.AccountReference = $actionContext.Data.employeeId

#region functions
function Get-MSEntraCertificate {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [string]
        $CertificateBase64String,

        [parameter(Mandatory)]
        [string]
        $CertificatePassword
    )
    try {        
        $rawCertificate = [system.convert]::FromBase64String($CertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [Parameter(Mandatory)]
        $Certificate,

        [parameter(Mandatory)]
        [string]
        $TenantID,

        [parameter(Mandatory)]
        [string]
        $AppId
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$($AppId)"
            'sub' = "$($AppId)"
            'aud' = "https://login.microsoftonline.com/$($TenantID)/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # This also supports CNG instead of only CAPI 
        $rsaPrivate = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        $signatureInput = "$base64Header.$base64Payload"
        $bytesToSign = [Text.Encoding]::UTF8.GetBytes($signatureInput)
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256
        $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        $signature = $rsaPrivate.SignData($bytesToSign, $hashAlgorithm, $padding)
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')
        $jwtToken = "$base64Header.$base64Payload.$base64Signature"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://database.windows.net'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($TenantID)/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Invoke-SQLQuery {
    param(
        [parameter(Mandatory = $true)]
        $ConnectionString,

        [parameter(Mandatory = $false)]
        $AccessToken,

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

        # Connect to the SQL server
        $SqlConnection = [System.Data.SqlClient.SqlConnection]::new()
        $SqlConnection.ConnectionString = "$ConnectionString"
        
        # Use AccessToken if provided, otherwise use SQL credentials
        if (-not[String]::IsNullOrEmpty($AccessToken)) {
            # Azure SQL authentication using AccessToken
            $SqlConnection.AccessToken = $AccessToken
        }
        elseif (-not[String]::IsNullOrEmpty($Username) -and -not[String]::IsNullOrEmpty($Password)) {
            # Local SQL authentication using credentials
            $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $credential = [System.Management.Automation.PSCredential]::new($Username, $securePassword)
            $credential.Password.MakeReadOnly()
            $sqlCredential = [System.Data.SqlClient.SqlCredential]::new($credential.username, $credential.password)
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
    $actionMessage = "initializing connection to SQL database"
        
    if ($actionContext.configuration.azureSqlAuthentication -eq $true) {
        $certificate = Get-MSEntraCertificate -CertificateBase64String $actionContext.configuration.azureSqlAppCertificateBase64String -CertificatePassword $actionContext.configuration.azureSqlAppCertificatePassword
        $accessToken = Get-MSEntraAccessToken -Certificate $certificate -TenantID $actionContext.configuration.azureSqlTenantID -AppId $actionContext.configuration.azureSqlAppId
    }
    else {
        $accessToken = $null
    }

    foreach ($attributeName in $attributeNames) {
        # Check if attribute is in table
        $actionMessage = "querying row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)]"

        $attributeValue = $actionContext.Data.$attributeName -Replace "'", "''"

        $querySelect = "SELECT * FROM [$table] WHERE [attributeName] = '$attributeName' AND [attributeValue] = '$attributeValue'"

        $querySelectSplatParams = @{
            ConnectionString = $actionContext.configuration.connectionString
            AccessToken      = $accessToken
            Username         = $actionContext.configuration.username
            Password         = $actionContext.configuration.password
            SqlQuery         = $querySelect
            ErrorAction      = "Stop"
        }
                
        $querySelectResult = [System.Collections.ArrayList]::new()
        Invoke-SQLQuery @querySelectSplatParams -Data ([ref]$querySelectResult) -verbose:$false

        $selectRowCount = ($querySelectResult | Measure-Object).count
        Write-Information "Queried data FROM [$table] WHERE [attributeName] = '$attributeName' AND [attributeValue] = '$attributeValue'. Result count: $selectRowCount"

        # Calculate action
        $actionMessage = "calculating action"

        # If multiple rows are found, filter additionally for employeeId
        if ($selectRowCount -gt 1) {
            $correlatedAccount = $querySelectResult | Where-Object { $_.employeeId -eq $actionContext.Data.employeeId }
            $selectRowCount = ($correlatedAccount | Measure-Object).count
        
            Write-Information "Multiple rows found where [$($attributeName)] = [$($actionContext.Data.$attributeName)]. Filtered additionally for employeeId. Result count: $selectRowCount"
        }
        else {
            $correlatedAccount = $querySelectResult
        }

        if ($selectRowCount -eq 1) {                
            # Check if value belongs to someone else
            if ($correlatedAccount.employeeId -ne $actionContext.Data.employeeId) {
                # Check retention period if value is deleted
                if (-NOT [string]::IsNullOrEmpty($correlatedAccount.whenDeleted)) {
                    $whenDeletedDate = [datetime]($correlatedAccount.whenDeleted)
                    $daysDiff = (New-TimeSpan -Start $whenDeletedDate -End (Get-Date)).Days
                        
                    if ($daysDiff -lt $retentionPeriod) {
                        $action = "OtherEmployeeId"
                    }
                    else {
                        # Retention period expired, can reuse
                        $action = "Update"
                    }
                }
                else {
                    # Value belongs to someone else and not deleted
                    $action = "OtherEmployeeId"
                }
            }
            else {
                # Value belongs to current employee
                if (-not([string]::IsNullOrEmpty($correlatedAccount.whenDeleted))) {
                    # Clear whenDeleted to reactivate
                    $action = "Update"
                }
                else {
                    $action = "NoChanges" 
                }
            }
        }
        elseif ($selectRowCount -eq 0) {
            $action = "Create"
        }
        elseif ($selectRowCount -gt 1) {
            $action = "MultipleFound"
        }

        # Update blocklist database
        switch ($action) {
            "Create" {
                # Create row
                $actionMessage = "creating row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)] AND [employeeID] = [$($actionContext.Data.employeeId)]"

                # Create new object for insert
                $insertObject = [PSCustomObject]@{
                    employeeId     = $actionContext.Data.employeeId
                    attributeName  = $attributeName
                    attributeValue = $attributeValue
                    whenCreated    = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fff")
                    whenUpdated    = $null
                    whenDeleted    = $null
                }

                # Enclose Property Names with brackets [] & Enclose Property Values with single quotes ''
                $queryInsertProperties = $("[" + (($insertObject.PSObject.Properties.Name) -join "],[") + "]")
                $queryInsertValues = $(($insertObject.PSObject.Properties.Value | ForEach-Object { if ($_ -ne 'null' -and $null -ne $_) { "'$_'" } else { 'null' } }) -join ',')
                $queryInsert = "INSERT INTO $table ($($queryInsertProperties)) VALUES ($($queryInsertValues))"

                $queryInsertSplatParams = @{
                    ConnectionString = $actionContext.configuration.connectionString
                    AccessToken      = $accessToken
                    Username         = $actionContext.configuration.username
                    Password         = $actionContext.configuration.password
                    SqlQuery         = $queryInsert
                    ErrorAction      = "Stop"
                }
                
                $outputContext.Data | Add-Member -NotePropertyName $attributeName -NotePropertyValue $attributeValue -Force

                if (-not($actioncontext.dryRun -eq $true)) {
                    $queryInsertResult = [System.Collections.ArrayList]::new()
                    Invoke-SQLQuery @queryInsertSplatParams -Data ([ref]$queryInsertResult)

                    $outputContext.auditlogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Created row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)] AND [employeeID] = [$($actionContext.Data.employeeId)]."
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would create row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)] AND [employeeID] = [$($actionContext.Data.employeeId)]."
                }

                break
            }
            
            "Update" {
                # Update row - clear whenDeleted and update employeeId (either for current employee or reusing expired row)
                $actionMessage = "updating [employeeId] to [$($updateObject.employeeId)] and [whenDeleted] to [$($updateObject.whenDeleted)] for row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)]"

                # Create new object for update
                $updateObject = [PSCustomObject]@{
                    employeeId  = $actionContext.Data.employeeId
                    whenDeleted = $null
                    whenUpdated = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fff")
                }

                # Build SET clause from updateObject properties
                $queryUpdateSet = "SET " + (($updateObject.PSObject.Properties | ForEach-Object { 
                            if ($_.Value -eq $null) { 
                                "[$($_.Name)]=null"
                            }
                            else { 
                                "[$($_.Name)]='$($_.Value)'" 
                            } 
                        }) -join ', ')
                $queryUpdate = "UPDATE [$table] $queryUpdateSet WHERE [attributeValue] = '$attributeValue' AND [attributeName] = '$attributeName'"

                $queryUpdateSplatParams = @{
                    ConnectionString = $actionContext.configuration.connectionString
                    AccessToken      = $accessToken
                    Username         = $actionContext.configuration.username
                    Password         = $actionContext.configuration.password
                    SqlQuery         = $queryUpdate
                    ErrorAction      = "Stop"
                }
                
                $outputContext.Data | Add-Member -NotePropertyName $attributeName -NotePropertyValue $attributeValue -Force

                if (-not($actioncontext.dryRun -eq $true)) {
                    $queryUpdateResult = [System.Collections.ArrayList]::new()
                    Invoke-SQLQuery @queryUpdateSplatParams -Data ([ref]$queryUpdateResult)

                    $outputContext.auditlogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Updated [employeeId] to [$($updateObject.employeeId)] and [whenDeleted] to [$($updateObject.whenDeleted)] for row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)]."
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would update [employeeId] to [$($updateObject.employeeId)] and [whenDeleted] to [$($updateObject.whenDeleted)] for row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)]."
                }

                break
            }

            "NoChanges" {
                $actionMessage = "skipping updating row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)] AND [employeeID] = [$($actionContext.Data.employeeId)]"

                $outputContext.Data | Add-Member -NotePropertyName $attributeName -NotePropertyValue $correlatedAccount.attributeValue -Force

                $outputContext.auditlogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Skipped updating row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)] AND [employeeID] = [$($actionContext.Data.employeeId)]. reason: No changes."
                        IsError = $false
                    })

                break
            }

            "OtherEmployeeId" {
                $actionMessage = "updating row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)]"

                # Throw terminal error
                throw "A row was found where [$($attributeName)] = [$($actionContext.Data.$attributeName)]. However the EmployeeID [$($correlatedAccount.employeeId)] doesn't match the current person (expected: [$($actionContext.Data.employeeId)]). Additionally, [whenDeleted] = [$($correlatedAccount.whenDeleted)] is still within the allowed threshold [$retentionPeriod days]. This should not be possible. Please check the database for inconsistencies."
                
                break
            }

            "MultipleFound" {
                $actionMessage = "updating row in table [$table] where [$($attributeName)] = [$($actionContext.Data.$attributeName)]"

                # Throw terminal error
                throw "Multiple rows were found in the database where [$($attributeName)] = [$($actionContext.Data.$attributeName)] AND [employeeID] = [$($actionContext.Data.employeeId)]. This should not be possible. Please check the database for inconsistencies."
                
                break
            }
        }
    }
}
catch {
    $ex = $PSItem

    $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
    $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

    Write-Warning $warningMessage

    $outputContext.auditlogs.Add([PSCustomObject]@{
            # Action  = "" # Optional
            Message = $auditMessage
            IsError = $true
        })
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-not($outputContext.auditlogs.IsError -contains $true)) {
        $outputContext.success = $true
    }
}