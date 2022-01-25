Function Connect-GoogleClassroom
{
    [CmdletBinding(DefaultParameterSetName='NoParameters')]
    param(
        [parameter(
            Position=0,
            ParameterSetName = 'ForceReauthentication',
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
            [Switch]$ForceReauthentication,

        [parameter(
            Position=1,
            ParameterSetName = 'ForceRefresh',
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
            [Switch]$ForceRefresh
)


    # Info: https://developers.google.com/identity/protocols/oauth2#installed:~:text=The%20Google%20OAuth%202.0%20endpoint%20supports%20applications%20that%20are,token%20to%20obtain%20a%20new%20one.
    # The Google OAuth 2.0 endpoint supports applications that are installed on devices such as computers, mobile devices, and tablets.
    # When you create a client ID through the Google API Console, specify that this is an Installed application, then select Android, Chrome app,
    # iOS, Universal Windows Platform (UWP), or Desktop app as the application type.
    # The process results in a client ID and, in some cases, a client secret, which you embed in the source code of your application.
    # (In this context, the client secret is obviously not treated as a secret.)
    # The authorization sequence begins when your application redirects a browser to a Google URL;
    # the URL includes query parameters that indicate the type of access being requested. Google handles the user authentication, session selection, and user consent.
    # The result is an authorization code, which the application can exchange for an access token and a refresh token.
    # The application should store the refresh token for future use and use the access token to access a Google API.
    # Once the access token expires, the application uses the refresh token to obtain a new one.
    
    # Get the config and set the connection information
    $google_classroom_config = Get-GoogleClassroomConfig -ConfigPath $google_classroom_api_config_file_path
    $client_id = $google_classroom_config.client_id
    $project_id = $google_classroom_config.project_id
    $auth_uri = $google_classroom_config.auth_uri
    $token_uri = $google_classroom_config.token_uri
    $auth_provider_x509_cert_url = $google_classroom_config.auth_provider_x509_cert_url
    $client_secret = $google_classroom_config.client_secret
    $redirect_uris = $google_classroom_config.redirect_uris

    # Load Web assembly
     [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

     # Build authorisation URI
     $scopes = 'https://www.googleapis.com/auth/classroom.courses https://www.googleapis.com/auth/classroom.rosters https://www.googleapis.com/auth/classroom.guardianlinks.students'
     $strUri = $auth_uri +
     "?client_id=$client_id" +
     "&redirect_uri=" + [System.Web.HttpUtility]::UrlEncode($redirect_uris[0]) + # Note that this array has 2 URIs, but we just use the 1st one which has Google provide a code that you would copy & paste.
     '&scope=' + [System.Web.HttpUtility]::UrlEncode($scopes) +
     '&response_type=code'

    # If key file does not exist or the ForceReauthentication parameter is sent, go and get a new one-time use authorization code
    # so you can exchange for an access token and a refresh token.
    if ((-not (Test-Path $google_clasroom_api_tokens_file_path)) -or ($ForceReauthentication))
    {
        Get-NewTokens -google_classroom_api_tokens_file_path $google_clasroom_api_tokens_file_path
    }

    # Get Tokens & Set Creation Times
    try
    {
        $Authorization = Get-AuthTokensFromFile
        $refresh_token_creation = $Authorization.refresh_token_creation
        $access_token_creation = $Authorization.access_token_creation    
    }
    catch
    {
        throw "JSON token file is corrupted or invalid. Please run Connect-GoogleClassroom with the -ForceReauthentication parameter to recreate it."  
    }

    # If Refresh Token Has Expired Because it Hasn't Been Used for Max Refresh Token Timespan, Ask User to Reauthenticate
    if (-not (Confirm-TokenIsFresh -TokenCreation $refresh_token_creation -TokenType Refresh))
    {
        Get-NewTokens -google_classroom_api_tokens_file_path $google_clasroom_api_tokens_file_path

        # Get Tokens & Set Creation Times
        try
        {
            $Authorization = Get-AuthTokensFromFile
            $refresh_token_creation = $Authorization.refresh_token_creation
            $access_token_creation = $Authorization.access_token_creation    
        }
        catch
        {
            throw "JSON token file is expired, corrupted or invalid. Please run Connect-GoogleClassroom with the -ForceReauthentication parameter to recreate it." 
        }
    }

    # If the Access Token Expired OR the -ForceRefresh Parameter is Set, Then Refresh Access Token      
    if ((-not (Confirm-TokenIsFresh -TokenCreation $access_token_creation -TokenType Access)) -or ($ForceRefresh))
    {
        # Run Invoke Command and Catch Responses
        [int]$InvokeCount = 0
        [int]$MaxInvokeCount = 5
        do
        {      
            $InvokeCount += 1
            $NextAction = $null
            try
            {
                $Authorization = Get-AuthTokensFromFile
                $Authorization = Get-AccessToken -client_id $client_id -client_secret $client_secret -refresh_token $($Authorization.refresh_token) -refresh_token_creation $($Authorization.refresh_token_creation) 
            }
            catch
            {
                # Process Invoke Error
                $NextAction = CatchInvokeErrors($_)

                # Just in case the token was refreshed by the error catcher, update the $Authorization variable
                $Authorization = Get-AuthTokensFromFile
            }
        }while ($NextAction -eq 'retry' -and $InvokeCount -lt $MaxInvokeCount)

        if ($InvokeCount -ge $MaxInvokeCount)
        {
            throw "Invoke tried running $InvokeCount times, but failed each time.`n" `
            + "JSON token file is corrupted or invalid. Please run Connect-GoogleClassroom with the -ForceReauthentication parameter to recreate it."
        }
            
        # Save credentials to file
        $Authorization | Select-Object access_token, refresh_token, refresh_token_creation, access_token_creation | ConvertTo-Json `
            | ConvertTo-SecureString -AsPlainText -Force `
            | ConvertFrom-SecureString `
            | Out-File -FilePath $google_clasroom_api_tokens_file_path -Force
    }
}
