function Get-GoogleClassroomConfig
{
    <#
        .SYNOPSIS
        Get the configuration and secrets to connect to your Google Classroom API application.
        .DESCRIPTION
        Get the configuration and secrets to connect to your Google Classroom API application.
        .EXAMPLE
        Get-GoogleClassroomConfig -ConfigPath $google_classroom_api_config_file_path
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
        Position=0,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigPath = $google_classroom_api_config_file_path # If not entered will see if it can pull path from this variable.
    )
    
    # Make Sure Requested Path Isn't Null or Empty
    if ([string]::IsNullOrEmpty($ConfigPath))
    {
        throw "Cannot validate argument on parameter `'ConfigPath`'. The argument is null or empty. Provide an argument that is not null or empty, and then try the command again."
    }

    try {
        # Get Config and Secrets
        Write-Verbose -Message 'Getting content of the Google Classroom API configuration JSON file and returning as a PSCustomObject.'
        $google_classroom_config = Get-Content -Path "$ConfigPath" -ErrorAction 'Stop' | ConvertFrom-Json

        $google_classroom_config = [PSCustomObject] @{
            client_id = ($google_classroom_config | Select-Object -Property "installed").installed.client_id
            project_id = ($google_classroom_config | Select-Object -Property "installed").installed.project_id
            auth_uri = ($google_classroom_config | Select-Object -Property "installed").installed.auth_uri
            token_uri = ($google_classroom_config | Select-Object -Property "installed").installed.token_uri
            auth_provider_x509_cert_url = ($google_classroom_config | Select-Object -Property "installed").installed.auth_provider_x509_cert_url
            client_secret = ($google_classroom_config | Select-Object -Property "installed").installed.client_secret
            redirect_uris = ($google_classroom_config | Select-Object -Property "installed").installed.redirect_uris
        }

        return $google_classroom_config
    } catch {
        throw "Can't find the JSON configuration file. Please check your path or download the OAuth config (client id & secret) file from your Google Cloud project."
    }
}