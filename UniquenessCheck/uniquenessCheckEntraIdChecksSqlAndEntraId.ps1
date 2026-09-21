#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-UniquenessCheck
# Check if fields are unique
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Script Configuration, only Required for ExchangeOnlineIntegration.
$correlationField = 'employeeId'
$correlationValue = $personContext.Person.ExternalId

$entraMailboxFallbackLookupProperty = 'givenName'
$entraMailboxFallbackLookupPropertyValue = $personContext.Person.ExternalId

# SQL Configuration
$table = $actionContext.Configuration.table
[int]$retentionPeriod = $actionContext.Configuration.retentionPeriod

# Correlation Attribute
# Identifies and matches persons between the account data (from HelloID) and the blocklist database
# Used to determine ownership of values: does a blocklisted value belong to the current person or someone else?
# Required for: Self-usage checks, retention period validation, and ownership determination
#
# IMPORTANT: The accountFieldName specified here MUST be mapped in your field mapping configuration
# for ALL operations where this uniqueness check is used (create, update, etc.).
# If this field is not mapped or is empty, the uniqueness check cannot function correctly.
$correlationAttribute = [PSCustomObject]@{
    accountFieldName = "employeeId"  # Property name in the account data received from HelloID - MUST be mapped in field mapping!
    systemFieldName  = "employeeId"  # Corresponding column name in the blocklist database table
}

# Allow Self-Usage Configuration
# Determines whether a person can reuse values they already own in the blocklist database
# - $true (recommended): Person's own values are treated as unique
#   Example: Person can keep their existing email address without triggering non-unique warnings
# - $false (strict mode): Person's own values are also treated as non-unique
#   Example: Forces regeneration of all values, even if the person already owns them
$allowSelfUsage = $true

#region functions
function Resolve-MS-Entra-ExoError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }

        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
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
            'iss' = "$($actionContext.Configuration.appId)"
            'sub' = "$($actionContext.Configuration.appId)"
            'aud' = "https://login.microsoftonline.com/$($actionContext.Configuration.tenantID)/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Extract the private key from the certificate
        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Ensure the certificate has a private key
        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $actionContext.Configuration.appId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($actionContext.Configuration.tenantID)/oauth2/token"
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

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($actionContext.Configuration.appCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $actionContext.Configuration.appCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraSqlAccessToken {
    [CmdletBinding()]
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

        $createAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://database.windows.net'
        }

        $createAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($TenantID)/oauth2/token"
            Body        = $createAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createAccessTokenResponse = Invoke-RestMethod @createAccessTokenSplatParams
        Write-Output $createAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraSqlCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($actionContext.Configuration.azureSqlAppCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $actionContext.Configuration.azureSqlAppCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
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

#region Fields to check
$fieldsToCheck = [PSCustomObject]@{
    'userPrincipalName'             = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'userPrincipalName' # Name of the field in Entra ID (Graph API) and attributeName in the SQL blocklist table.
        accountValue    = $actionContext.Data.userPrincipalName
        keepInSyncWith  = @('mail', 'mailNickname') # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = @('mail') # Properties to cross-check for uniqueness.
    }
    'mail'                          = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'mail' # Name of the field in Entra ID (Graph API) and attributeName in the SQL blocklist table.
        accountValue    = $actionContext.Data.mail
        keepInSyncWith  = @('userPrincipalName', 'mailNickname') # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = @('userPrincipalName') # Properties to cross-check for uniqueness.
    }
    'mailNickname'                  = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'mailNickname' # Name of the field in Entra ID (Graph API) and attributeName in the SQL blocklist table.
        accountValue    = $actionContext.Data.mailNickname
        keepInSyncWith  = @('userPrincipalName', 'mail') # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = $null # Properties to cross-check for uniqueness.
    }
    'exchangeOnline.emailAddresses' = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        systemFieldName = 'proxyAddresses' # Name of the field in Entra ID (Graph API) and attributeName in the SQL blocklist table.
        accountValue    = $actionContext.Data.exchangeOnline.emailAddresses
        keepInSyncWith  = @('userPrincipalName', 'mail', 'mailNickname') # Properties to synchronize with. If this property isn't unique, these properties will also be treated as non-unique.
        crossCheckOn    = $null # Properties to cross-check for uniqueness.
    }
}
#endregion Fields to check

try {
    # Setup Connection with Entra/Exo
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    # Determine SQL authentication method based on configuration
    $sqlAccessToken = $null
    if ($actionContext.Configuration.azureSqlAuthentication -eq $true) {
        $actionMessage = 'retrieving Azure SQL access token'
        $sqlCertificate = Get-MSEntraSqlCertificate
        $sqlAccessToken = Get-MSEntraSqlAccessToken -Certificate $sqlCertificate -TenantID $actionContext.Configuration.azureSqlTenantID -AppId $actionContext.Configuration.azureSqlAppId
    }

    # Validate that correlation attribute is mapped and has a value
    if ([string]::IsNullOrEmpty($correlationAttribute.accountFieldName)) {
        throw "Correlation attribute 'accountFieldName' is not configured. This is a mandatory configuration setting."
    }
    if (-not ($actionContext.Data.PSObject.Properties.Name -contains $correlationAttribute.accountFieldName)) {
        throw "Correlation attribute [$($correlationAttribute.accountFieldName)] is not present in the account data. Please ensure this field is mapped in your HelloID field mapping configuration for all operations (create, update, etc.) where this uniqueness check is used."
    }
    if ([string]::IsNullOrEmpty($actionContext.Data.($correlationAttribute.accountFieldName))) {
        throw "Correlation attribute [$($correlationAttribute.accountFieldName)] exists in the account data but has no value. Please ensure this field is properly mapped with a valid value in your HelloID field mapping configuration."
    }
    Write-Information "Correlation attribute validation successful: [$($correlationAttribute.accountFieldName)] = [$($actionContext.Data.($correlationAttribute.accountFieldName))]"

    # Create Entra ID headers
    $actionMessage = 'creating Entra ID headers'
    $entraIDHeaders = @{
        'Accept'           = 'application/json'
        'Content-Type'     = 'application/json;charset=utf-8'
        'ConsistencyLevel' = 'eventual'
    }
    Write-Information "Created Entra ID headers. Result (without Authorization): $($entraIDHeaders | ConvertTo-Json)."
    # Add Authorization after printing splat
    $entraIDHeaders['Authorization'] = "Bearer $($entraToken)"

    # Verify account reference and perform correlation lookup if needed
    if ($actionContext.Operation.ToLower() -ne 'create') {
        $actionMessage = 'verifying account reference'
        if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
            throw 'The account reference could not be found'
        }
    }
    else {
        if ([string]::IsNullOrEmpty($correlationValue)) {
            throw 'The correlation value could not be found on the person'
        }
        # Get Entra account on correlation field
        $actionMessage = "querying MS-Entra account on correlation field where [$correlationField] = [$($correlationValue)]"
        $selectPropertiesToGetUser = ($outputContext.Data | Select-Object * -ExcludeProperty ExchangeOnline, managerId ).PSObject.Properties.Name -join ','
        $splatGetEntraUser = @{
            Uri     = "https://graph.microsoft.com/v1.0/users?`$filter=$correlationField eq '$($correlationValue)'&`$select=$selectPropertiesToGetUser"
            Method  = 'GET'
            Headers = @{'Authorization' = "Bearer $($entraToken)" }
        }
        $correlatedAccountEntra = (Invoke-RestMethod @splatGetEntraUser).value
        if ($correlatedAccountEntra.Count -eq 1) {
            $actionContext.References.Account = $correlatedAccountEntra.id
        }
        elseif ($correlatedAccountEntra.Count -eq 0) {
            # Get Entra account on Fallback field to handle ExchangeOnlineIntegration where the correlation field is not yet populated
            $actionMessage = "querying MS-Entra account on fallback field where [$entraMailboxFallbackLookupProperty] = [$($entraMailboxFallbackLookupPropertyValue)]"
            $selectPropertiesToGetUser = ($outputContext.Data | Select-Object * -ExcludeProperty ExchangeOnline, managerId ).PSObject.Properties.Name -join ','
            $splatGetEntraUser = @{
                Uri     = "https://graph.microsoft.com/v1.0/users?`$filter=$entraMailboxFallbackLookupProperty eq '$($entraMailboxFallbackLookupPropertyValue)'&`$select=$selectPropertiesToGetUser"
                Method  = 'GET'
                Headers = @{'Authorization' = "Bearer $($entraToken)" }
            }
            $correlatedAccountEntraFallBack = (Invoke-RestMethod @splatGetEntraUser).value
            if ($correlatedAccountEntraFallBack.Count -eq 1) {
                $actionContext.References.Account = $correlatedAccountEntraFallBack.id
            }
        }
    }

    foreach ($fieldToCheck in $fieldsToCheck.PsObject.Properties | Where-Object { -not[String]::IsNullOrEmpty($_.Value.accountValue) }) {
        # Skip if this field is already marked as non-unique
        if ($outputContext.NonUniqueFields -contains $fieldToCheck.Name) {
            Write-Verbose "Skipping uniqueness check for property [$($fieldToCheck.Name)] with value(s) [$($fieldToCheck.Value.accountValue -join ', ')] because it is already marked as non-unique (either directly or through keepInSyncWith configuration)."
            continue
        }

        #region SQL Check
        foreach ($fieldToCheckAccountValue in $fieldToCheck.Value.accountValue) {
            # Remove smtp: prefix for proxyAddresses/emailAddresses
            $fieldToCheckAccountValue = $fieldToCheckAccountValue -replace '(?i)^smtp:', ''

            # Escape single quotes to prevent SQL errors and injection for values like "in 't veld"
            $sqlAccountValue = $fieldToCheckAccountValue.Replace("'", "''")

            # Build WHERE clause starting with the primary field
            $whereClause = "[attributeName] = '$($fieldToCheck.Value.systemFieldName)' AND [attributeValue] = '$sqlAccountValue'"

            # Add cross-check conditions if configured
            if (@($fieldToCheck.Value.crossCheckOn).Count -ge 1) {
                foreach ($fieldToCrossCheckOn in $fieldToCheck.Value.crossCheckOn) {
                    $crossCheckSystemFieldName = $fieldsToCheck.$fieldToCrossCheckOn.systemFieldName

                    # Custom check for exchangeOnline.emailAddresses to prefix value with 'smtp:'
                    if ($fieldToCrossCheckOn -eq 'exchangeOnline.emailAddresses') {
                        $whereClause = $whereClause + " OR ([attributeName] = '$crossCheckSystemFieldName' AND [attributeValue] = 'smtp:$sqlAccountValue')"
                    }
                    else {
                        $whereClause = $whereClause + " OR ([attributeName] = '$crossCheckSystemFieldName' AND [attributeValue] = '$sqlAccountValue')"
                    }
                }
            }

            $querySelect = "SELECT * FROM [$table] WHERE $whereClause"
            $querySelectSplatParams = @{
                ConnectionString = $actionContext.Configuration.connectionString
                AccessToken      = $sqlAccessToken
                Username         = $actionContext.Configuration.username
                Password         = $actionContext.Configuration.password
                SqlQuery         = $querySelect
                ErrorAction      = "Stop"
            }

            $querySelectResult = [System.Collections.ArrayList]::new()
            Invoke-SQLQuery @querySelectSplatParams -Data ([ref]$querySelectResult)
            $selectRowCount = ($querySelectResult | Measure-Object).Count
            Write-Verbose "Queried data from table [$table] for attribute [$($fieldToCheck.Name)] with cross-check. Query: $querySelect. Returned rows: $selectRowCount"

            if ($selectRowCount -gt 0) {
                foreach ($dbRow in $querySelectResult) {
                    # Check if the person is using the value themselves (based on correlation attribute)
                    if ($dbRow.($correlationAttribute.systemFieldName) -eq $actionContext.Data.($correlationAttribute.accountFieldName)) {
                        if ($allowSelfUsage) {
                            Write-Information "Person is using property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] themselves in SQL blocklist. Continuing with Entra ID availability check."
                        }
                        else {
                            # Self-usage is not allowed - treat as non-unique
                            Write-Warning "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is not unique. Person is using this value themselves, but self-usage is disabled (allowSelfUsage = false). [$($correlationAttribute.systemFieldName)]: [$($dbRow.($correlationAttribute.systemFieldName))]."
                            [void]$outputContext.NonUniqueFields.Add($fieldToCheck.Name)
                            if (@($fieldToCheck.Value.keepInSyncWith).Count -ge 1) {
                                foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $actionContext.Data.PsObject.Properties.Name }) {
                                    Write-Warning "Property [$fieldToKeepInSyncWith] is marked as non-unique because it is configured to keepInSyncWith [$($fieldToCheck.Name)], which is not unique."
                                    [void]$outputContext.NonUniqueFields.Add($fieldToKeepInSyncWith)
                                }
                            }
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
                            if ($dbRow.attributeName -eq $fieldToCheck.Value.systemFieldName) {
                                Write-Warning "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is not unique. It is currently in use by [$($correlationAttribute.systemFieldName)]: [$($dbRow.($correlationAttribute.systemFieldName))]. The associated [whenDeleted] timestamp [$($dbRow.whenDeleted)] is still within the allowed retention period of [$($retentionPeriod) days]."
                            }
                            else {
                                Write-Warning "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is not unique due to cross-check. The value exists as [$($dbRow.attributeName)] = [$($dbRow.attributeValue)] in use by [$($correlationAttribute.systemFieldName)]: [$($dbRow.($correlationAttribute.systemFieldName))]. The associated [whenDeleted] timestamp [$($dbRow.whenDeleted)] is still within the allowed retention period of [$($retentionPeriod) days]."
                            }
                            [void]$outputContext.NonUniqueFields.Add($fieldToCheck.Name)
                            if (@($fieldToCheck.Value.keepInSyncWith).Count -ge 1) {
                                foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $actionContext.Data.PsObject.Properties.Name }) {
                                    Write-Warning "Property [$fieldToKeepInSyncWith] is marked as non-unique because it is configured to keepInSyncWith [$($fieldToCheck.Name)], which is not unique."
                                    [void]$outputContext.NonUniqueFields.Add($fieldToKeepInSyncWith)
                                }
                            }
                            break
                        }
                        else {
                            Write-Information "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] is reusable based on SQL retention. Although it was previously used by [$($correlationAttribute.systemFieldName)]: [$($dbRow.($correlationAttribute.systemFieldName))], the [whenDeleted] timestamp [$($dbRow.whenDeleted)] exceeds the allowed retention period of [$($retentionPeriod) days]. Continuing with Entra ID availability check."
                        }
                    }
                }
            }
            elseif ($selectRowCount -eq 0) {
                Write-Information "Property [$($fieldToCheck.Name)] with value [$fieldToCheckAccountValue] was not found in SQL blocklist. Continuing with Entra ID availability check."
            }
        }
        #endregion SQL Check

        # If SQL already marked this field as non-unique, skip Entra ID check
        if ($outputContext.NonUniqueFields -contains $fieldToCheck.Name) {
            continue
        }

        #region Entra ID Check
        $actionMessage = "calculating filter account for property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)]"

        # Custom check for exchangeOnline.emailAddresses to verify against proxyAddresses in Entra ID.
        # This is necessary to check in Entra ID (instead of Exchange Online) because changes in Exchange Online reflect in Entra ID, but not all changes in Entra ID reflect in Exchange Online.
        # Additionally, this check is unique as it deals with an array of values.
        $filter = $null
        if ($fieldToCheck.Value.systemFieldName -eq 'proxyAddresses') {
            foreach ($fieldToCheckAccountValue in $fieldToCheck.Value.accountValue) {
                # Escape single quotes to prevent filter errors and injection for values like "in 't veld"
                $entraIdAccountValue = "$fieldToCheckAccountValue".Replace("'", "''")

                if ($null -eq $filter) {
                    $filter = "$($fieldToCheck.Value.systemFieldName)/any(c:c eq '$($entraIdAccountValue)')" 
                }
                else {
                    $filter = $filter + " OR $($fieldToCheck.Value.systemFieldName)/any(c:c eq '$($entraIdAccountValue)')"
                }
            }
        }
        else {
            $entraIdAccountValue = "$($fieldToCheck.Value.accountValue)".Replace("'", "''")
            $filter = "$($fieldToCheck.Value.systemFieldName) eq '$($entraIdAccountValue)'" 
        }

        if (@($fieldToCheck.Value.crossCheckOn).Count -ge 1) {
            $crossCheckEntraIdAccountValue = "$($fieldToCheck.Value.accountValue)".Replace("'", "''")
            foreach ($fieldToCrossCheckOn in $fieldToCheck.Value.crossCheckOn) {
                $filter = $filter + " OR $($fieldToCrossCheckOn) eq '$($crossCheckEntraIdAccountValue)'"
            }
        }

        $actionMessage = "querying Entra ID account where [filter] = [$filter]"
        try {
            $correlatedAccount = $null
            $splatGetEntraUser = @{
                Uri    = "https://graph.microsoft.com/v1.0/users?`$filter=$($filter)&`$select=id,$($fieldToCheck.Value.systemFieldName)&`$count=true"
                Method = 'GET'
            }
            Write-Information "splatGetEntraUser: $($splatGetEntraUser | ConvertTo-Json)"
            # Add headers after printing splat
            $splatGetEntraUser['Headers'] = $entraIDHeaders
            $correlatedAccount = (Invoke-RestMethod @splatGetEntraUser -Verbose:$false).Value
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq 404) {
                throw "Entra Account [$($actionContext.References.Account)] could not be found, possibly indicating that it could be deleted"
            }
            else {
                throw $_
            }
        }
        Write-Information "Queried Entra ID account where [filter] = [$filter]. Result count: $(@($correlatedAccount).Count)"

        # Check property uniqueness
        $actionMessage = "checking if property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is unique"
        if (@($correlatedAccount).count -gt 0) {
            # Check if the person is using the value themselves
            if (-not [string]::IsNullOrEmpty($actionContext.References.Account) -and $correlatedAccount.id -eq $actionContext.References.Account) {
                Write-Information "Person is using property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] themselves in Entra ID."
            }
            else {
                Write-Information "Property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is not unique. In use by account with ID: $($correlatedAccount.id)"
                [void]$outputContext.NonUniqueFields.Add($fieldToCheck.Name)
                if (@($fieldToCheck.Value.keepInSyncWith).Count -ge 1) {
                    foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $actionContext.Data.PsObject.Properties.Name }) {
                        Write-Warning "Property [$fieldToKeepInSyncWith] is marked as non-unique because it is configured to keepInSyncWith [$($fieldToCheck.Name)], which is not unique."
                        [void]$outputContext.NonUniqueFields.Add($fieldToKeepInSyncWith)
                    }
                }
            }
        }
        elseif (@($correlatedAccount).count -eq 0) {
            Write-Information "Property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is unique across SQL blocklist and Entra ID."
        }
        #endregion Entra ID Check
    }

    # Set Success to true
    $outputContext.Success = $true
}
catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    Write-Warning $warningMessage
    # Required to write an error as uniqueness check doesn't show auditlog
    Write-Error $auditMessage
}
finally {
    $outputContext.NonUniqueFields = @($outputContext.NonUniqueFields | Sort-Object -Unique)
}