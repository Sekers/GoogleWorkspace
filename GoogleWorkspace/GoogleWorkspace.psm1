# Google Workspae API Module
# More info available at https://developers.google.com/classroom & https://developers.google.com/identity/protocols/oauth2

# Configure script to use TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Set Global User Data Path Variable
New-Variable -Name 'google_api_user_data_path' -Value "$([Environment]::GetEnvironmentVariable('LOCALAPPDATA'))\GoogleClassroom PowerShell" -Scope Global -Force

# Type Definitions

# Google Classroom API
# Public Enum
# Name: CourseState (https://developers.google.com/classroom/reference/rest/v1/courses#CourseState)
# Value: COURSE_STATE_UNSPECIFIED - No course state. No returned Course message will use this value.
# Value: ACTIVE - The course is active.
# Value: ARCHIVED - The course has been archived. You cannot modify it except to change it to a different state.
# Value: PROVISIONED - The course has been created, but not yet activated. It is accessible by the primary teacher and domain administrators, who may modify it or change it to the ACTIVE or DECLINED states. A course may only be changed to PROVISIONED if it is in the DECLINED state.
# Value: DECLINED - The course has been created, but declined. It is accessible by the course owner and domain administrators, though it will not be displayed in the web UI. You cannot modify the course except to change it to the PROVISIONED state. A course may only be changed to DECLINED if it is in the PROVISIONED state.
# Value: SUSPENDED - The course has been suspended. You cannot modify the course, and only the user identified by the ownerId can view the course. A course may be placed in this state if it potentially violates the Terms of Service.

# Check to see if the CourseState Type is already loading to prevent the "Cannot add type. The type name 'CourseState' already exists." error message. 
if ("CourseState" -as [type]) {} else {
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
}

# Functions
function Set-GoogleWorkspaceConfigFilePath
{
    param (
        [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Path
    )
    
    New-Variable -Name 'google_workspace_api_config_file_path' -Value $Path -Scope Global -Force
}

function Set-GoogleWorkspaceTokensFilePath
{
    param (
        [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$Path
    )
   
    New-Variable -Name 'google_workspace_api_tokens_file_path' -Value $Path -Scope Global -Force
}

function Set-GoogleWorkspaceScopes
{
    param (
        [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$Scopes #Array of strings
    )
   
    # Convert $Scopes from an array of strings to a space-delimited string.
    [string]$Scopes = $Scopes -join ' '
    New-Variable -Name 'google_workspace_api_scopes' -Value $Scopes -Scope Global -Force
}

function Get-GoogleWorkspaceAuthTokensFromFile
{
    param (
    )

    try
    {
        $apiTokens = Get-Content $google_workspace_api_tokens_file_path -ErrorAction Stop
        $SecureString = $apiTokens | ConvertTo-SecureString -ErrorAction Stop
        $AuthTokensFromFile = ((New-Object PSCredential "user",$SecureString).GetNetworkCredential().Password) | ConvertFrom-Json
    }
    catch
    {
        throw "JSON token file is missing, corrupted or invalid. Please run Connect-GoogleWorkspace with the -ForceReauthentication parameter to recreate it."    
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

Function Show-GoogleAPIOAuthWindow
{
    Param(
        [parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [System.Uri]$Url,

        [parameter(
        Position=1,
        Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('','EdgeWebView2','MiniHTTPServer')] # Allows null to be passed
        [string]$AuthenticationMethod,

        [parameter(
        Position=2,
        Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [switch]$ClearBrowserControlCache
    )
    # This will request a Google access token (https://developers.google.com/identity/protocols/oauth2#2.-obtain-an-access-token-from-the-google-authorization-server.)
    # Uses the Loopback IP option:  https://developers.google.com/identity/protocols/oauth2/native-app#redirect-uri_loopback

    # If Edge WebView 2 is the Authentication Method & the runtime not installed - https://developer.microsoft.com/en-us/microsoft-edge/webview2/
    # If you run the following command from an elevated process or command prompt, it triggers a per-machine install.
    # If you don't run the command from an elevated process or command prompt, a per-user install will take place.
    #However, a per-user install is automatically replaced by a per-machine install, if a per-machine Microsoft Edge Updater is in place.
    #A per-machine Microsoft Edge Updater is provided as part of Microsoft Edge, except for the Canary preview channel of Microsoft Edge.
    #For more information, see https://docs.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution#installing-the-runtime-as-per-machine-or-per-user.
    if ($null -eq $AuthenticationMethod -or "" -eq $AuthenticationMethod -or $AuthenticationMethod -eq "EdgeWebView2")
    {
        # Check if WebView2 is installed
        $SourceProductName = 'Microsoft Edge WebView2 Runtime' # Partial Name is Fine as Long as it is Unique enough for a match

        # Get a Listing of Installed Applications From the Registry
        $InstalledApplicationsFromRegistry = @()
        $InstalledApplicationsFromRegistry += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" # HKLM Apps
        $InstalledApplicationsFromRegistry += Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" #HKCU Apps
        if ([System.Environment]::Is64BitProcess)
        {
            $InstalledApplicationsFromRegistry += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" # x86 Apps when on 64-bit
        }
        
        # Get EdgeWebView2 Installed Version (only pull the 1st entry in case more than one comes up)
        $EdgeWebViewVersionInstalled = $InstalledApplicationsFromRegistry | Where-Object {$_.DisplayName -match $SourceProductName}
        if ([string]::IsNullOrEmpty($EdgeWebViewVersionInstalled))
        {
            $EdgeWebViewVersionInstalled = "0.0.0.0" # Good idea to set something in case it's not installed due to casting later on.
        }
        else
        {
            $EdgeWebViewVersionInstalled = $([array]($InstalledApplicationsFromRegistry | Where-Object {$_.DisplayName -match $SourceProductName})[0]).Version
        }

        while ((-not ($InstalledApplicationsFromRegistry | Where-Object {$_.DisplayName -match $SourceProductName})) -and ($null -eq $AuthenticationMethod -or "" -eq $AuthenticationMethod -or $AuthenticationMethod -eq "EdgeWebView2") )
        {
            Write-Warning "Microsoft Edge WebView2 Runtime is not installed and is required for browser-based authentication. Please install the runtime and try again."
            $PromptNoWebView2Runtime_Title = "Options"
            $PromptNoWebView2Runtime_Message = "Enter your choice:"
            $PromptNoWebView2Runtime_Choices = [System.Management.Automation.Host.ChoiceDescription[]]@("&Download & install the Edge WebView2 runtime", "&Try alternative method (beta)", "&Cancel & exit")
            $PromptNoWebView2Runtime_Default = 0
            $PromptNoWebView2Runtime_Selection = $host.UI.PromptForChoice($PromptNoWebView2Runtime_Title,$PromptNoWebView2Runtime_Message,$PromptNoWebView2Runtime_Choices,$PromptNoWebView2Runtime_Default)

            switch($PromptNoWebView2Runtime_Selection)
            {
                0   {
                        Write-Host "Attempting to download & install the Microsoft Edge WebView2 runtime"
                        # Create Download Folder If It Doesn't Already Exist
                        $DownloadPath = "$google_api_user_data_path\Downloads"
                        $null = New-Item -ItemType Directory -Path $DownloadPath -Force

                        # Download WebView2 Evergreen Bootstrapper
                        $DownloadURL = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
                        $DownloadContent = Invoke-WebRequest -Uri $DownloadURL
                        $DownloadFileName = "Microsoft Edge WebView2 Runtime Installer.exe"

                        # Create the file (this will overwrite any existing file with the same name)
                        $WebView2Installer = [System.IO.FileStream]::new("$DownloadPath\$DownloadFileName", [System.IO.FileMode]::Create)
                        $WebView2Installer.Write($DownloadContent.Content, 0, $DownloadContent.RawContentLength)
                        $WebView2Installer.Close()

                        # Install
                        Write-Host "File Downloaded. Attempting to run installer."
                        Start-Process -Filepath "$DownloadPath\$DownloadFileName" -Wait

                        # Get a Listing of Installed Applications From the Registry
                        $InstalledApplicationsFromRegistry = @()
                        $InstalledApplicationsFromRegistry += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" # HKLM Apps
                        $InstalledApplicationsFromRegistry += Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" #HKCU Apps
                        if ([System.Environment]::Is64BitProcess)
                        {
                            $InstalledApplicationsFromRegistry += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" # x86 Apps when on 64-bit
                        }

                        # Retry Opening Authentication Window
                        Write-Host "Retrying Authentication...`n"
                    }
                1   {
                        $AuthenticationMethod = "MiniHTTPServer"
                    }
                2   {
                        Write-Host "Exiting..."
                        Exit
                    }
            }
        }
    }

    switch ($AuthenticationMethod)
    {
        MiniHTTPServer # TODO
        {
            Write-Host "`nUsing this option will attempt to authenticate using an alternate method by building a mini webserver in PowerShell. Continue?"
            $PromptMiniWebserver_Title = "Options"
            $PromptMiniWebserver_Message = "Enter your choice:"
            $PromptMiniWebserver_Choices = [System.Management.Automation.Host.ChoiceDescription[]]@("&Load temporary HTTP server", "&Cancel & exit")
            $PromptMiniWebserver_Default = 0
            $PromptMiniWebserver_Selection = $host.UI.PromptForChoice($PromptMiniWebserver_Title,$PromptMiniWebserver_Message,$PromptMiniWebserver_Choices,$PromptMiniWebserver_Default)

            switch($PromptMiniWebserver_Selection)
            {
                0   {
                        Write-Warning "Sorry. The mini webserver authentication feature is not yet implemented."
                        Write-Host "Exiting..."
                        Exit
                    }
                1   {
                        Write-Host "Exiting..."
                        Exit
                    }
            }
        }
        default # EdgeWebView2
        {            
            # Set EdgeWebView2 Control Version to Use
            $EdgeWebView2Control_VersionNumber = '1.0.1518.46'
            switch ($PSVersionTable.PSEdition)
            {
                Desktop {$EdgeWebView2Control_DotNETVersion = "net45"}
                Core {$EdgeWebView2Control_DotNETVersion = "netcoreapp3.0"}
                Default {$EdgeWebView2Control_DotNETVersion = "netcoreapp3.0"}
            }
            switch ([System.Environment]::Is64BitProcess)
            {
                $true {$EdgeWebView2Control_OSArchitecture = "win-x64"}
                $false {$EdgeWebView2Control_OSArchitecture = "win-x86"}
                Default {$EdgeWebView2Control_OSArchitecture = "win-x64"}
            }
            
            # Update $AuthenticationMethod Variable (not currently needed but is useful to have in a variable)
            $AuthenticationMethod = "EdgeWebView2"
            
            # Load Assemblies
            Add-Type -AssemblyName System.Windows.Forms

            # Unpack the nupkg and grab the following two DLLs out of the /lib folder.
            # - Microsoft.Web.WebView2.WinForms.dll (there's a different version for each .NET type, but the same file for x86 & x64)
            # - Microsoft.Web.WebView2.Core.dll (while there's a copy for each .NET type, so far they have been the same exact file; same file for x86 & x64 too)
            # In addition, get the following file from the /runtimes folder and put it in the same locations.
            # - WebView2Loader.dll (different for x86 & x64, but same for .NET Core & .NET 45)
            Add-Type -Path "$PSScriptRoot\Dependencies\Microsoft.Web.WebView2\$EdgeWebView2Control_VersionNumber\$EdgeWebView2Control_DotNETVersion\$EdgeWebView2Control_OSArchitecture\Microsoft.Web.WebView2.WinForms.dll"

            $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width=600;Height=800}
            $WebView2 = New-Object -TypeName Microsoft.Web.WebView2.WinForms.WebView2

            $WebView2.CreationProperties = New-Object -TypeName 'Microsoft.Web.WebView2.WinForms.CoreWebView2CreationProperties'
            $WebView2.CreationProperties.UserDataFolder = $google_api_user_data_path

            # Clear WebView2 cache in the previously specified UserDataFolder, if requested.
            # Using the WebView2 SDK to clear the browsing data is best, but wasn't released until version 1.0.1245.22 of the control.
            # This version SDK requires EdgeWebView2 version 102.0.1245.22 to be installed for full API compatibility.
            # So, we only clear the cache using the SDK if this version or higher of the WebView2 runtime is installed.
            # Otherwise, we just hardcode deleting the folder.
            # Note that we have to delete the folder before the control is loaded,
            # but we can't call the clear until it is initialized (so that code is further down).
            if ($ClearBrowserControlCache -and [System.Version]$EdgeWebViewVersionInstalled -lt [System.Version]'102.0.1245.22')
            {
                Remove-Item "$($WebView2.CreationProperties.UserDataFolder)\EBWebView\Default" -Force -Recurse -ErrorAction Ignore
                $ClearBrowserControlCache = $false
            }

            $WebView2.Source = $Url
            $WebView2.Size = New-Object System.Drawing.Size(584, 760)

            # Set Event Handlers. See APIs here: https://github.com/MicrosoftEdge/WebView2Browser#webview2-apis
            $WebView2_NavigationCompleted = {
                # Write-Host $($WebView2.Source.AbsoluteUri) # DEBUG LINE
                if ($WebView2.Source.AbsoluteUri -match "error=[^&]*|$([regex]::escape($redirect_uri))*")
                {
                    $form.Close()
                }
            }
            $WebView2.add_NavigationCompleted($WebView2_NavigationCompleted)

            # Set Event Handler for Clearing the Browser Data, if requested.
            # We can't actually clear the browser data until the CoreWebView2 property is created, so that's why it's down here as an event action.
            # More info: https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.winforms.webview2
            # This event is triggered when the control's CoreWebView2 has finished being initialized
            # (regardless of how initialization was triggered) but before it is used for anything.
            # More info: https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.wpf.webview2.corewebview2initializationcompleted
            if ($ClearBrowserControlCache -and [System.Version]$EdgeWebViewVersionInstalled -ge [System.Version]'102.0.1245.22')
            {
                $WebView2_CoreWebView2InitializationCompleted = {
                    $WebView2.CoreWebView2.Profile.ClearBrowsingDataAsync()
                }
                $WebView2.add_CoreWebView2InitializationCompleted($WebView2_CoreWebView2InitializationCompleted)
                $ClearBrowserControlCache = $false
            }
            
            # Add WebView2 Control to the Form and Show It
            $form.Controls.Add($WebView2)
            $form.Add_Shown({$form.Activate()})
            $form.TopMost = $true # Make's the dialog coming up above the PowerShell console more consistent (though not 100% it seems).
            $form.ShowDialog() | Out-Null

            # Parse Return URL
            $queryOutput = [System.Web.HttpUtility]::ParseQueryString($WebView2.Source.Query)
            $output = @{}
            foreach($key in $queryOutput.Keys){
                $output["$key"] = $queryOutput[$key]
            }

            # Dispose Form & Webview2 Control
            $WebView2.Dispose()
            $form.Dispose()
        }
    }

    # Validate the $output variable before returning
    if ($null -eq $output["code"]) {
        Write-Warning "Authentication or authorization failed. Try again?"
        $PromptNoAuthCode_Title = "Options"
        $PromptNoAuthCode_Message = "Enter your choice:"
        $PromptNoAuthCode_Choices = [System.Management.Automation.Host.ChoiceDescription[]]@("&Yes", "&No; exit the script")
        $PromptNoAuthCode_Default = 0
        $PromptNoAuthCode_Selection = $host.UI.PromptForChoice($PromptNoAuthCode_Title,$PromptNoAuthCode_Message,$PromptNoAuthCode_Choices,$PromptNoAuthCode_Default)

        switch($PromptNoAuthCode_Selection)
        {
            0   { # Retry authenticating & authorizing
                    $authOutput = Show-GoogleAPIOAuthWindow -url $Url -AuthenticationMethod $AuthenticationMethod -ClearBrowserControlCache:$ClearBrowserControlCache
                    return $authOutput
                }
            1   {
                    throw "Authentication or authorization failed. Exiting..."
                }
        }
    }

    Return $output
}

Function Get-GoogleAPINewTokens
{
    [CmdletBinding()]
    Param(
        
    [parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$google_workspace_api_tokens_file_path,

        [parameter(
        Position=1,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$google_workspace_api_scopes,
    
        [parameter(
        Position=2,
        Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('','EdgeWebView2','MiniHTTPServer')] # Allows null to be passed
        [string]$AuthenticationMethod,

        [parameter(
        Position=3,
        Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [switch]$ClearBrowserControlCache


    )

    # Set the necessary configuration variables.
    $google_workspace_config = Get-GoogleWorkspaceConfig -ConfigPath $google_workspace_api_config_file_path
    $client_id = $google_workspace_config.client_id
    # $project_id = $google_workspace_config.project_id # Not used.
    $auth_uri = $google_workspace_config.auth_uri
    $token_uri = $google_workspace_config.token_uri
    # $auth_provider_x509_cert_url = $google_workspace_config.auth_provider_x509_cert_url # Not used.
    $client_secret = $google_workspace_config.client_secret
    $redirect_uri = $google_workspace_config.redirect_uri

    # Load Web assembly
    [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    # Build authorisation URI
    $strUri = $auth_uri +
    "?client_id=$client_id" +
    "&redirect_uri=" + [System.Web.HttpUtility]::UrlEncode($redirect_uri) +
    '&scope=' + [System.Web.HttpUtility]::UrlEncode($google_workspace_api_scopes) +
    '&response_type=code'

    # Get Authorization code (one-time use code)
    $authOutput = Show-GoogleAPIOAuthWindow -Url $strUri -AuthenticationMethod $AuthenticationMethod -ClearBrowserControlCache:$ClearBrowserControlCache

    # Swap authorization code (one-time use) for an access token and a refresh token.
    # Build tokens request
    $AuthorizationPostRequest = 'client_id=' + $client_id + '&' +
    'client_secret=' + [System.Web.HttpUtility]::UrlEncode($client_secret) + '&' +
    'redirect_uri=' + [System.Web.HttpUtility]::UrlEncode($redirect_uri) + '&' +
    'code=' + [System.Web.HttpUtility]::UrlEncode($authOutput["code"]) + '&' +
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
        $google_workspace_api_tokens_file_path_ParentDir = Split-Path -Path $google_workspace_api_tokens_file_path
        If(-not (Test-Path $google_workspace_api_tokens_file_path))
        {
            $null = New-Item -ItemType Directory -Force -Path $google_workspace_api_tokens_file_path_ParentDir
        }

        # Add Access & Refresh Token expirys to PSCustomObject and Save credentials to file
        $Authorization | Add-Member -MemberType NoteProperty -Name "refresh_token_creation" -Value $((Get-Date).ToUniversalTime().ToString("o")) -Force
        $Authorization | Add-Member -MemberType NoteProperty -Name "access_token_creation" -Value $((Get-Date).ToUniversalTime().ToString("o")) -Force
                
        # Save credentials to file
        $Authorization | Select-Object refresh_token, access_token, refresh_token_creation, access_token_creation | ConvertTo-Json `
            | ConvertTo-SecureString -AsPlainText -Force `
            | ConvertFrom-SecureString `
            | Out-File -FilePath $google_workspace_api_tokens_file_path -Force
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
    $Authorization = Get-GoogleWorkspaceAuthTokensFromFile

    # Reconnect If the Access Token is Expired 
    if (-NOT (Confirm-TokenIsFresh -TokenCreation $Authorization.access_token_creation -TokenType Access))
    {
        Connect-GoogleWorkspace -ForceRefresh
        $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
    }

    # Create Request Uri
    $uid = [uri]::EscapeDataString($uid)
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
            $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
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
    $Authorization = Get-GoogleWorkspaceAuthTokensFromFile

    # Reconnect If the Access Token is Expired 
    if (-NOT (Confirm-TokenIsFresh -TokenCreation $Authorization.access_token_creation -TokenType Access))
    {
        Connect-GoogleWorkspace -ForceRefresh
        $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
    }

    # Create Request Uri
    $uid = [uri]::EscapeDataString($uid)
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
                    $pageRecordCount = $apiItems.count # Not currently used but can be useful for troubleshooting.
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
            $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
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
    $Authorization = Get-GoogleWorkspaceAuthTokensFromFile

    # Reconnect If the Access Token is Expired 
    if (-NOT (Confirm-TokenIsFresh -TokenCreation $Authorization.access_token_creation -TokenType Access))
    {
        Connect-GoogleWorkspace -ForceRefresh
        $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
    }

    # Create Request Uri
    $uid = [uri]::EscapeDataString($uid)
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
            $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
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
    $Authorization = Get-GoogleWorkspaceAuthTokensFromFile

    # Reconnect If the Access Token is Expired 
    if (-NOT (Confirm-TokenIsFresh -TokenCreation $Authorization.access_token_creation -TokenType Access))
    {
        Connect-GoogleWorkspace -ForceRefresh
        $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
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
    $uid = [uri]::EscapeDataString($uid)
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
            $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
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
    $Authorization = Get-GoogleWorkspaceAuthTokensFromFile

    # Reconnect If the Access Token is Expired 
    if (-NOT (Confirm-TokenIsFresh -TokenCreation $Authorization.access_token_creation -TokenType Access))
    {
        Connect-GoogleWorkspace -ForceRefresh
        $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
    }

    # Create Request Uri
    $uid = [uri]::EscapeDataString($uid)
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
            $Authorization = Get-GoogleWorkspaceAuthTokensFromFile
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
    $InvokeError_Code = $InvokeErrorMessageConvertedFromJSON.code
    $InvokeError_Message = $InvokeErrorMessageConvertedFromJSON.message
    $InvokeError_Errors = $InvokeErrorMessageConvertedFromJSON.errors
    $InvokeError_Status = $InvokeErrorMessageConvertedFromJSON.status
    $InvokeError_Details = $InvokeErrorMessageConvertedFromJSON.details

    Switch ($InvokeError_Code)
    {
        400 # Bad request. Usually means that data in the initial request is invalid, improperly formatted or failed a precondition.
        {
            throw $InvokeErrorMessageConvertedFromJSON
        }
        401 # Unauthorized Request (Unauthenticated). Could mean that the authenticated user does not have rights to access the requested data or does not have permission to edit a given record or record type.
            # An unauthorized request also occurs if the authorization token expires or if the authorization header is not supplied (i.e., credentials used are invalid).
        {
            # Usually this happens if the token has expired.
            Connect-GoogleWorkspace -ForceRefresh
            'retry'
        }
        403 # An error 403 occurs for many reasons. Officially, it's "PERMISSION_DENIED" but is also used when users, etc. don't exist or are not part of the course admin's domain.
        {
            switch ($InvokeError_Details.reason)
            {
                ACCESS_TOKEN_SCOPE_INSUFFICIENT
                {
                    throw "Request had insufficient authentication scopes. Please run Connect-GoogleWorkspace with the -ForceReauthentication parameter and include the necessary OAuth scopes."
                }
                Default
                {
                    throw $InvokeErrorMessageConvertedFromJSON
                }
            }
        }
        429 # Rate limit is exceeded (Too many requests). Try again in 1 seconds. 
        {
            # Sleep for 1 second and return the try command.
            Start-Sleep -Seconds 1
            'retry'
        }
        500 # Internal Server Error (Backend error). 
        {
            # Sleep for 5 seconds and return the try command. I don't know if this is a good length, but it seems reasonable since we try 5 times before failing.
            # The other option would be to use the exponential backoff method where You can periodically retry a failed request over an increasing amount of time to handle errors
            # related to rate limits, network volume, or response time. For example, you might retry a failed request after one second, then after two seconds, and then after four seconds.
            Start-Sleep -Seconds 5
            'retry'
        }
        503 # The service is currently unavailable.
        {
            # Sleep for 5 seconds and return the try command. I don't know if this is a good length, but it seems reasonable since we try 5 times before failing.
            # The other option would be to use the exponential backoff method where You can periodically retry a failed request over an increasing amount of time to handle errors
            # related to rate limits, network volume, or response time. For example, you might retry a failed request after one second, then after two seconds, and then after four seconds.
            Start-Sleep -Seconds 5
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
