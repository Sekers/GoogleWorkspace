Function Connect-GoogleWorkspace
{
        <#
        .LINK
        https://github.com/Sekers/GoogleWorkspaceAPI

        .SYNOPSIS
        Google API - Verify cached tokens exist and are not expired using Connect-GoogleWorkspace.
        Connect-GoogleWorkspace will automatically refresh tokens or reauthenticate to the Google API service, if necessary.

        .DESCRIPTION
        Google API - Verify cached tokens exist and are not expired using Connect-GoogleWorkspace.
        Connect-GoogleWorkspace will automatically refresh tokens or reauthenticate to the Google API service, if necessary.

        .PARAMETER ForceReauthentication
        Forces reauthentication.
        .PARAMETER ForceRefresh
        Forces token refresh.
        .PARAMETER ClearBrowserControlCache 
        Used in conjunction with 'ForceReauthentication'. Clears the Microsoft Edge WebView2 control browser cache. Useful when troubleshooting authentication.
        .PARAMETER AuthenticationMethod
        Let's you specify how you want to authenticate if authentication is necessary:
        - EdgeWebView2 (default):   Opens a web browser window using Microsoft Edge WebView2 for authentication.
                                    Requires the WebView2 Runtime to be installed. If not installed, will prompt for automatic installation.
        - MiniHTTPServer:           Alternate method of capturing the authentication using your user account's default web browser
                                    and listening for the authentication response using a temporary HTTP server hosted by the module.

        .EXAMPLE
        Connect-GoogleWorkspace
        .EXAMPLE
        Connect-GoogleWorkspace -ForceReauthentication
        .EXAMPLE
        Connect-GoogleWorkspace -ForceReauthentication -ClearBrowserControlCache
        .EXAMPLE
        Connect-GoogleWorkspace -ForceReauthentication -AuthenticationMethod MiniHTTPServer
        .EXAMPLE
        Connect-GoogleWorkspace -ForceRefresh
    #>

    [CmdletBinding(DefaultParameterSetName='NoParameters')]
    Param(
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
        [Switch]$ForceRefresh,

        [parameter(
        Position=2,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('EdgeWebView2','MiniHTTPServer','ServiceAccount')] # TODO ServiceAccount
        [string]$AuthenticationMethod
    )

    DynamicParam
    {
        # Initialize Parameter Dictionary
        $ParameterDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
        
        # Make -ClearBrowserControlCache Parameter Only Appear if ForceReauthentication is Used
        # DynamicParameter1: ClearBrowserControlCache
        if ($ForceReauthentication)
        { 
            $ParameterAttributes = [System.Management.Automation.ParameterAttribute]@{
                ParameterSetName = "ForceReauthentication"
                Mandatory = $false
                ValueFromPipeline = $true
                ValueFromPipelineByPropertyName = $true
            }

            $AttributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
            $AttributeCollection.Add($ParameterAttributes)

            $DynamicParameter1 = [System.Management.Automation.RuntimeDefinedParameter]::new(
                'ClearBrowserControlCache', [switch], $AttributeCollection)

            $ParameterDictionary.Add('ClearBrowserControlCache', $DynamicParameter1)
        }

        return $ParameterDictionary
    }

    begin
    {
        $ClearBrowserControlCache = $PSBoundParameters['ClearBrowserControlCache']
    }

    process
    {
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
        $google_workspace_config = Get-GoogleWorkspaceConfig -ConfigPath $google_workspace_api_config_file_path
        $client_id = $google_workspace_config.client_id
        $client_secret = $google_workspace_config.client_secret

        # If key file does not exist or the ForceReauthentication parameter is sent, go and get a new one-time use authorization code
        # so you can exchange for an access token and a refresh token.
        if ((-not (Test-Path $google_workspace_api_tokens_file_path)) -or ($ForceReauthentication))
        {
            $HashArguments = @{
                google_workspace_api_tokens_file_path = $google_workspace_api_tokens_file_path
                google_workspace_api_scopes = $google_workspace_api_scopes
                AuthenticationMethod = $AuthenticationMethod
            }
            Get-GoogleAPINewTokens @HashArguments -ClearBrowserControlCache:$ClearBrowserControlCache
        }

        # Get Tokens & Set Creation Times
        try
        {
            $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
            $refresh_token_creation = $Authorization.refresh_token_creation
            $access_token_creation = $Authorization.access_token_creation    
        }
        catch
        {
            throw "JSON token file is corrupted or invalid. Please run Connect-GoogleWorkspace with the -ForceReauthentication parameter to recreate it."  
        }

        # If Refresh Token Has Expired Because it Hasn't Been Used for Max Refresh Token Timespan, Ask User to Reauthenticate
        if (-not (Confirm-TokenIsFresh -TokenCreation $refresh_token_creation -TokenType Refresh))
        {
            $HashArguments = @{
                google_workspace_api_tokens_file_path = $google_workspace_api_tokens_file_path
                google_workspace_api_scopes = $google_workspace_api_scopes
                AuthenticationMethod = $AuthenticationMethod
            }
            Get-GoogleAPINewTokens @HashArguments -ClearBrowserControlCache:$ClearBrowserControlCache

            # Get Tokens & Set Creation Times
            try
            {
                $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
                $refresh_token_creation = $Authorization.refresh_token_creation
                $access_token_creation = $Authorization.access_token_creation    
            }
            catch
            {
                throw "JSON token file is expired, corrupted or invalid. Please run Connect-GoogleWorkspace with the -ForceReauthentication parameter to recreate it." 
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
                    $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
                    $Authorization = Get-AccessToken -client_id $client_id -client_secret $client_secret -refresh_token $($Authorization.refresh_token) -refresh_token_creation $($Authorization.refresh_token_creation) 
                }
                catch
                {
                    # Process Invoke Error
                    $NextAction = CatchInvokeErrors($_)

                    # Just in case the token was refreshed by the error catcher, update the $Authorization variable
                    $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
                }
            }while ($NextAction -eq 'retry' -and $InvokeCount -lt $MaxInvokeCount)

            if ($InvokeCount -ge $MaxInvokeCount)
            {
                throw "Invoke tried running $InvokeCount times, but failed each time.`n" `
                + "JSON token file is corrupted or invalid. Please run Connect-GoogleWorkspace with the -ForceReauthentication parameter to recreate it."
            }
                
            # Save credentials to file
            $Authorization | Select-Object access_token, refresh_token, refresh_token_creation, access_token_creation | ConvertTo-Json `
                | ConvertTo-SecureString -AsPlainText -Force `
                | ConvertFrom-SecureString `
                | Out-File -FilePath $google_workspace_api_tokens_file_path -Force
        }
    }
}
