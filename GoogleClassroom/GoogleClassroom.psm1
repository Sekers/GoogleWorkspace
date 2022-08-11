# Google Classroom Module
# More info available at https://developers.google.com/classroom & https://developers.google.com/identity/protocols/oauth2

# Configure script to use TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Type Definitions

# Public Enum
# Name: CourseState (https://developers.google.com/classroom/reference/rest/v1/courses#CourseState)
# Value: COURSE_STATE_UNSPECIFIED - No course state. No returned Course message will use this value.
# Value: ACTIVE - The course is active.
# Value: ARCHIVED - The course has been archived. You cannot modify it except to change it to a different state.
# Value: PROVISIONED - The course has been created, but not yet activated. It is accessible by the primary teacher and domain administrators, who may modify it or change it to the ACTIVE or DECLINED states. A course may only be changed to PROVISIONED if it is in the DECLINED state.
# Value: DECLINED - The course has been created, but declined. It is accessible by the course owner and domain administrators, though it will not be displayed in the web UI. You cannot modify the course except to change it to the PROVISIONED state. A course may only be changed to DECLINED if it is in the PROVISIONED state.
# Value: SUSPENDED - The course has been suspended. You cannot modify the course, and only the user identified by the ownerId can view the course. A course may be placed in this state if it potentially violates the Terms of Service.

Add-Type -TypeDefinition @"
public enum CourseState {
    COURSE_STATE_UNSPECIFIED,
    ACTIVE,
    ARCHIVED,
    PROVISIONED,
    DECLINED,
    SUSPENDED
}
"@

# Functions
function Set-GoogleClassroomAPIConfigFilePath
{
    param (
        [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Path
    )
    
    New-Variable -Name 'google_classroom_api_config_file_path' -Value $Path -Scope Global -Force
}

function Set-GoogleClassroomAPITokensFilePath
{
    param (
        [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Path
    )
   
    New-Variable -Name 'google_clasroom_api_tokens_file_path' -Value $Path -Scope Global -Force
}

function Get-GoogleClassroomAuthTokensFromFile
{
    param (
    )

    try
    {
        $apiTokens = Get-Content $google_clasroom_api_tokens_file_path -ErrorAction Stop
        $SecureString = $apiTokens | ConvertTo-SecureString -ErrorAction Stop
        $AuthTokensFromFile = ((New-Object PSCredential "user",$SecureString).GetNetworkCredential().Password) | ConvertFrom-Json
    }
    catch
    {
        throw "JSON token file is missing, corrupted or invalid. Please run Connect-GoogleClassroom with the -ForceReauthentication parameter to recreate it."    
    }
    
    $AuthTokensFromFile
}

# Check to See if Refresh Token or Access Token is Expired
function Confirm-TokenIsFresh
{
    param (
        [parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [datetime]$TokenCreation,

        [parameter(
        Position=1,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('Refresh','Access')]
        [string]$TokenType
    )

    # For security purposes, access tokens will expire after 60 minutes.
    # Refresh tokens will also expire, but after a much longer period of time (https://developers.google.com/identity/protocols/oauth2#expiration).
    # --The user has revoked your app's access.
    # --The refresh token has not been used for six months.
    # --The user changed passwords and the refresh token contains Gmail scopes.
    # --The user account has exceeded a maximum number of granted (live) refresh tokens.
    # ----There is currently a limit of 50 refresh tokens per user account per client.
    # ----If the limit is reached, creating a new refresh token automatically invalidates the oldest refresh token without warning.
    # ----This limit does not apply to service accounts.
    $maxRefreshTokenTimespan = new-timespan -days 179
    $maxAccessTokenTimespan = new-timespan -minutes 59

    switch ($TokenType)
    {
        Refresh {$MaxTokenTimespan = $maxRefreshTokenTimespan}
        Access  {$MaxTokenTimespan = $maxAccessTokenTimespan}
    }

    if (((get-date) - $TokenCreation) -lt $MaxTokenTimespan)
    {
        $true
    }
    else
    {
        $false
    }
}

Function Get-AccessToken
{
    [CmdletBinding()]
    param($client_id,$client_secret,$refresh_token,$refresh_token_creation)

    #Build token request
    $AuthorizationPostRequest = 'client_id=' + $client_id + '&' +
    'client_secret=' + [System.Web.HttpUtility]::UrlEncode($client_secret) + '&' +
    'refresh_token=' + [System.Web.HttpUtility]::UrlEncode($refresh_token) + '&' +
    'grant_type=refresh_token'

    $token_uri = 'https://oauth2.googleapis.com/token'

    $Authorization =
        Invoke-RestMethod   -Method Post `
                            -ContentType application/x-www-form-urlencoded `
                            -Uri $token_uri `
                            -Body $AuthorizationPostRequest   
    
    # Add Refresh & Access Token expirys to PSCustomObject and Save credentials to file
    # Note that we update the refresh_token_creation date because it's a rolling expiration (expires six months from last use)
    $Authorization | Add-Member -MemberType NoteProperty -Name "access_token_creation" -Value $((Get-Date).ToUniversalTime().ToString("o")) -Force
    $Authorization | Add-Member -MemberType NoteProperty -Name "refresh_token_creation" -Value $((Get-Date).ToUniversalTime().ToString("o")) -Force
    
    # Since requesting access tokens doesn't provide a different refresh token (it just basically renews the existing one), add it back into the response. 
    $Authorization | Add-Member -Name "refresh_token" -Value $refresh_token -MemberType NoteProperty

    $Authorization
}

Function Show-OAuthWindow
{
    param(
        [System.Uri]$Url
    )

    # # This will request a Google access token (https://developers.google.com/identity/protocols/oauth2#2.-obtain-an-access-token-from-the-google-authorization-server.)

    Start-Process $Url
    $output = ""
    
    do
    {
        $output = Read-Host "Paste in the authorization code."
    }
    while ($null -eq $output -or $output -eq "")

    $output
}

Function Get-NewTokens
{
    [CmdletBinding()]
    param($google_classroom_api_tokens_file_path)

    # Get Authorization code (one-time use code)
    $authorization_code = Show-OAuthWindow -URL $strUri

    # Swap authorization code (one-time use) for an access token and a refresh token.
    # Build tokens request
    $AuthorizationPostRequest = 'client_id=' + $client_id + '&' +
    'client_secret=' + [System.Web.HttpUtility]::UrlEncode($client_secret) + '&' +
    'redirect_uri=' + [System.Web.HttpUtility]::UrlEncode($redirect_uris[0]) + '&' +
    'code=' + [System.Web.HttpUtility]::UrlEncode($authorization_code) + '&' +
    'grant_type=authorization_code'

    # Make the request
    $Authorization =
    Invoke-RestMethod   -Method Post `
                        -ContentType application/x-www-form-urlencoded `
                        -Uri $token_uri `
                        -Body $AuthorizationPostRequest

    # If the last command succeeded, write the tokens to a JSON file
    if ($?)
    {
        # Make sure path to credentials file exists and if it doesn't, create the parent folder
        $google_classroom_api_tokens_file_path_ParentDir = Split-Path -Path $google_classroom_api_tokens_file_path
        If(-not (Test-Path $google_classroom_api_tokens_file_path))
        {
            New-Item -ItemType Directory -Force -Path $google_classroom_api_tokens_file_path_ParentDir
        }

        # Add Access & Refresh Token expirys to PSCustomObject and Save credentials to file
        $Authorization | Add-Member -MemberType NoteProperty -Name "refresh_token_creation" -Value $((Get-Date).ToUniversalTime().ToString("o")) -Force
        $Authorization | Add-Member -MemberType NoteProperty -Name "access_token_creation" -Value $((Get-Date).ToUniversalTime().ToString("o")) -Force
                
        # Save credentials to file
        $Authorization | Select-Object refresh_token, access_token, refresh_token_creation, access_token_creation | ConvertTo-Json `
            | ConvertTo-SecureString -AsPlainText -Force `
            | ConvertFrom-SecureString `
            | Out-File -FilePath $google_classroom_api_tokens_file_path -Force
    }
    else
    {
        throw "Cannot create authorization token. Please try again."
    }    
}

Function Get-UnpagedEntity
{
    [CmdletBinding()]
    param($uid, $url, $endUrl, $params, $response_field)

    # Grab the keys
    $Authorization = Get-GoogleClassroomAuthTokensFromFile

    # Reconnect If the Access Token is Expired 
    if (-NOT (Confirm-TokenIsFresh -TokenCreation $Authorization.access_token_creation -TokenType Access))
    {
        Connect-GoogleClassroom -ForceRefresh
        $Authorization = Get-GoogleClassroomAuthTokensFromFile
    }

    # Create Request Uri
    $FullUri = $url + $uid + $endUrl
    $Request = [System.UriBuilder]$FullUri
    
    if ($null -ne $params -and $params -ne '') {
        $Request.Query = $params.ToString()
    }
    
    # Run Invoke Command and Catch Responses
    [int]$InvokeCount = 0
    [int]$MaxInvokeCount = 5
    do
    {      
        $InvokeCount += 1
        $NextAction = $null
        try
        {
            $apiCallResult =
            Invoke-RestMethod   -Method Get `
                                -ContentType application/json `
                                -Headers @{
                                        'Authorization' = ("Bearer "+ $($Authorization.access_token))} `
                                -Uri $($Request.Uri.AbsoluteUri)
            
            # If there is a response field return that
            if ($null -ne $response_field -and $response_field -ne "")
            {
                $apiCallResult.$response_field
            }
            else
            {
                $apiCallResult
            }
        }
        catch
        {
            # Process Invoke Error
            $NextAction = CatchInvokeErrors($_)
            $LastError = (ParseErrorForResponseBody($_) | ConvertFrom-Json).error

            # Just in case the token was refreshed by the error catcher, update these
            $Authorization = Get-GoogleClassroomAuthTokensFromFile
        }
    }while ($NextAction -eq 'retry' -and $InvokeCount -lt $MaxInvokeCount)

    if ($InvokeCount -ge $MaxInvokeCount)
    {
        throw $LastError
    }
}

Function Get-PagedEntity
{
    [CmdletBinding()]
    param($uid, $url, $endUrl, $params, $response_field,$response_limit)

    # Grab the keys
    $Authorization = Get-GoogleClassroomAuthTokensFromFile

    # Reconnect If the Access Token is Expired 
    if (-NOT (Confirm-TokenIsFresh -TokenCreation $Authorization.access_token_creation -TokenType Access))
    {
        Connect-GoogleClassroom -ForceRefresh
        $Authorization = Get-GoogleClassroomAuthTokensFromFile
    }

    # Create Request Uri
    $FullUri = $url + $uid + $endUrl
    $Request = [System.UriBuilder]$FullUri
    
    if ($null -ne $params -and $params -ne '') {
        $Request.Query = $params.ToString()
    }

    # Create records array
    $allRecords = @() 

    # Run Invoke Command and Catch Responses
    [int]$InvokeCount = 0
    [int]$MaxInvokeCount = 5
    do
    {      
        $InvokeCount += 1
        $NextAction = $null
        try
        {
            # Call to the API and loop unless the $page record count is 
            do
            {
                $apiItems =
                Invoke-RestMethod   -Method Get `
                                    -ContentType application/json `
                                    -Headers @{
                                            'Authorization' = ("Bearer "+ $($Authorization.access_token))} `
                                    -Uri $($Request.Uri.AbsoluteUri)
                
                # If there is a response field use that
                if ($null -ne $response_field -and $response_field -ne "")
                {
                    $allRecords += $apiItems.$response_field
                    $pageRecordCount = $apiItems.$response_field.count # Not currently used by can be useful for troubleshooting.
                }
                else # No Response Field
                {
                    $allRecords += $apiItems
                    $pageRecordCount = $apiItems.count # Not currently used by can be useful for troubleshooting.
                }
                
                $totalRecordCount = $allRecords.count

                # Set $pageToken location for the next page if it exists
                if ($null -ne $apiItems.nextPageToken -and $apiItems.nextPageToken -ne "")
                {
                    [string]$params['pageToken'] = $apiItems.nextPageToken
                    $Request.Query = $params.ToString()
                } 

                # If the user supplied a limit, then respect it and don't get subsequent pages
                if (($null -ne $response_limit -and $response_limit -ne 0 -and $response_limit -ne "") -and $response_limit -le $totalRecordCount)
                {
                    # If we have too many records, remove the extra ones
                    if ($totalRecordCount -gt $response_limit)
                    {
                        $allRecords = $allRecords[0..($response_limit - 1)]
                    }
                
                    return $allRecords
                }
                
            }
            while ($null -ne $apiItems.nextPageToken -and $apiItems.nextPageToken -ne "") # Loop to the next page if there is a nextPageToken

            $allRecords
        }
        catch
        {
            # Process Invoke Error
            $NextAction = CatchInvokeErrors($_)
            $LastError = (ParseErrorForResponseBody($_) | ConvertFrom-Json).error

            # Just in case the token was refreshed by the error catcher, update these
            $Authorization = Get-GoogleClassroomAuthTokensFromFile
        }
    }while ($NextAction -eq 'retry' -and $InvokeCount -lt $MaxInvokeCount)

    if ($InvokeCount -ge $MaxInvokeCount)
    {
        throw $LastError
    }
}

function Submit-Entity
{
    param ($uid, $url, $endUrl, $params)

    # Grab the keys
    $Authorization = Get-GoogleClassroomAuthTokensFromFile

    # Reconnect If the Access Token is Expired 
    if (-NOT (Confirm-TokenIsFresh -TokenCreation $Authorization.access_token_creation -TokenType Access))
    {
        Connect-GoogleClassroom -ForceRefresh
        $Authorization = Get-GoogleClassroomAuthTokensFromFile
    }

    # Create Request Uri
    $FullUri = $url + $uid + $endUrl
    $Request = [System.UriBuilder]$FullUri

    # Build Body
    if ($null -ne $params -and $params -ne '') {
        foreach ($param in $params)
        {
           $key_name = $param
           $key_value = $params[$param]
           $PostRequest += @{$key_name = $key_value}
        }
    }
   
    $PostRequest = $PostRequest | ConvertTo-Json

    # Run Invoke Command and Catch Responses
    [int]$InvokeCount = 0
    [int]$MaxInvokeCount = 5
    do
    {      
        $InvokeCount += 1
        $NextAction = $null
        try
        {
            Invoke-RestMethod   -Method Post `
            -ContentType application/json `
            -Headers @{
                    'Authorization' = ("Bearer "+ $($Authorization.access_token))} `
            -Uri $($Request.Uri.AbsoluteUri) `
            -Body $PostRequest
        }
        catch
        {
            # Process Invoke Error
            $NextAction = CatchInvokeErrors($_)
            $LastError = (ParseErrorForResponseBody($_) | ConvertFrom-Json).error

            # Just in case the token was refreshed by the error catcher, update these
            $Authorization = Get-GoogleClassroomAuthTokensFromFile
        }
    }while ($NextAction -eq 'retry' -and $InvokeCount -lt $MaxInvokeCount)

    if ($InvokeCount -ge $MaxInvokeCount)
    {
        throw $LastError
    }
}

function Update-Entity
{
    param ($uid, $url, $endUrl, $params)

    # Grab the keys
    $Authorization = Get-GoogleClassroomAuthTokensFromFile

    # Reconnect If the Access Token is Expired 
    if (-NOT (Confirm-TokenIsFresh -TokenCreation $Authorization.access_token_creation -TokenType Access))
    {
        Connect-GoogleClassroom -ForceRefresh
        $Authorization = Get-GoogleClassroomAuthTokensFromFile
    }

    # Build Body & Update Mask
    if ($null -ne $params -and $params -ne '') {
        $updateMask = "?updateMask="
        foreach ($param in $params)
        {
           $key_name = $param
           $key_value = $params[$param]
           $PatchRequest += @{$key_name = $key_value}

           $updateMask += $key_name + ","
        }
        # Remove extra comma at end
        $updateMask = $updateMask.TrimEnd(",")
    }

    $PatchRequest = $PatchRequest | ConvertTo-Json

    # Create Request Uri
    $FullUri = $url + $uid + $updateMask + $endUrl
    $Request = [System.UriBuilder]$FullUri

    # Run Invoke Command and Catch Responses
    [int]$InvokeCount = 0
    [int]$MaxInvokeCount = 5
    do
    {      
        $InvokeCount += 1
        $NextAction = $null
        try
        {
            Invoke-RestMethod   -Method Patch `
            -ContentType application/json `
            -Headers @{
                    'Authorization' = ("Bearer "+ $($Authorization.access_token))} `
            -Uri $($Request.Uri.AbsoluteUri) `
            -Body $PatchRequest
        }
        catch
        {
            # Process Invoke Error
            $NextAction = CatchInvokeErrors($_)
            $LastError = (ParseErrorForResponseBody($_) | ConvertFrom-Json).error

            # Just in case the token was refreshed by the error catcher, update these
            $Authorization = Get-GoogleClassroomAuthTokensFromFile
        }
    }while ($NextAction -eq 'retry' -and $InvokeCount -lt $MaxInvokeCount)

    if ($InvokeCount -ge $MaxInvokeCount)
    {
        throw $LastError
    }
}

function Remove-Entity
{
    param ($uid, $url, $endUrl)

    # Grab the keys
    $Authorization = Get-GoogleClassroomAuthTokensFromFile

    # Reconnect If the Access Token is Expired 
    if (-NOT (Confirm-TokenIsFresh -TokenCreation $Authorization.access_token_creation -TokenType Access))
    {
        Connect-GoogleClassroom -ForceRefresh
        $Authorization = Get-GoogleClassroomAuthTokensFromFile
    }

    # Create Request Uri
    $FullUri = $url + $uid + $endUrl
    $Request = [System.UriBuilder]$FullUri

    # Run Invoke Command and Catch Responses
    [int]$InvokeCount = 0
    [int]$MaxInvokeCount = 5
    do
    {      
        $InvokeCount += 1
        $NextAction = $null
        try
        {
            Invoke-RestMethod   -Method Delete `
            -ContentType application/json `
            -Headers @{
                    'Authorization' = ("Bearer "+ $($Authorization.access_token))} `
            -Uri $($Request.Uri.AbsoluteUri) `
        }
        catch
        {
            # Process Invoke Error
            $NextAction = CatchInvokeErrors($_)
            $LastError = (ParseErrorForResponseBody($_) | ConvertFrom-Json).error

            # Just in case the token was refreshed by the error catcher, update these
            $Authorization = Get-GoogleClassroomAuthTokensFromFile
        }
    }while ($NextAction -eq 'retry' -and $InvokeCount -lt $MaxInvokeCount)

    if ($InvokeCount -ge $MaxInvokeCount)
    {
        throw $LastError
    }
}

# Handle Common Errors > https://developers.google.com/classroom/guides/errors
# Request Errors > https://developers.google.com/classroom/reference/Request.Errors
# Access Errors > https://developers.google.com/classroom/reference/Access.Errors


function CatchInvokeErrors($InvokeError)
{
    # Convert From JSON
    $InvokeError_Parsed = ParseErrorForResponseBody($InvokeError)
    $InvokeErrorMessageConvertedFromJSON = ($InvokeError_Parsed | ConvertFrom-Json).error

    # Get Status Code, or Error if Code is blank
    $StatusCodeorError = 
        If($InvokeErrorMessageConvertedFromJSON.code)
        {
            $InvokeErrorMessageConvertedFromJSON.code
        }
        else
        {
            If($InvokeErrorMessageConvertedFromJSON.status)
            {
                $InvokeErrorMessageConvertedFromJSON.status
            }
            else
            {
                {$InvokeErrorMessageConvertedFromJSON.message}
            }
        }

    Switch ($StatusCodeorError)
    {
        400 # Bad request. Usually means that data in the initial request is invalid, improperly formatted or failed a precondition.
        {
            throw $InvokeErrorMessageConvertedFromJSON
        }
        401 # Unauthorized Request (Unauthenticated). Could mean that the authenticated user does not have rights to access the requested data or does not have permission to edit a given record or record type.
            # An unauthorized request also occurs if the authorization token expires or if the authorization header is not supplied (i.e., credentials used are invalid).
        {
            # Usually this happens if the token has expired.
            Connect-GoogleClassroom -ForceRefresh
            'retry'
        }
        403 # An error 403 occurs for many reasons. Officially, it's "PERMISSION_DENIED" but is also used when users, etc. don't exist or are not part of the course admin's domain.
        {
            throw $InvokeErrorMessageConvertedFromJSON
        }
        429 # Rate limit is exceeded (Too many requests). Try again in 1 seconds. 
        {
            # Sleep for 1 second and return the try command.
            Start-Sleep -Seconds 1
            'retry'
        }
        500 # Internal Server Error (Backend error). 
        {
            # Sleep for 100 second and return the try command. I don't know if this is too long, but it seems reasonable for now.
            # The other option would be to use the exponential backoff method where You can periodically retry a failed request over an increasing amount of time to handle errors
            # related to rate limits, network volume, or response time. For example, you might retry a failed request after one second, then after two seconds, and then after four seconds.
            Start-Sleep -Seconds 100
            'retry'
        }
        default
        {
            throw $InvokeErrorMessageConvertedFromJSON
        }
    }    
}

function ParseErrorForResponseBody($Err)
{
    # See https://stackoverflow.com/questions/18771424/how-to-get-powershell-invoke-restmethod-to-return-body-of-http-500-code-response
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if ($Err.Exception.Response) {  
            $Reader = New-Object System.IO.StreamReader($Err.Exception.Response.GetResponseStream())
            $Reader.BaseStream.Position = 0
            $Reader.DiscardBufferedData()
            $ResponseBody = $Reader.ReadToEnd()
            return $ResponseBody
        }
    }
    else {
        return $Err.ErrorDetails.Message
    }
}

# Import the functions
$GoogleClassroomFunctions = @(Get-ChildItem -Path $PSScriptRoot\Functions\*.ps1)

Foreach($GoogleClassroomFunction in $GoogleClassroomFunctions)
{
    # Write-Host "Importing $GoogleClassroomFunction"
    Try
    {
        . $GoogleClassroomFunction.fullname
    }
    Catch
    {
        Write-Error -Message "Failed to import function $($GoogleClassroomFunction.fullname): $_"
    }
}
