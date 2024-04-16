    <#
        .LINK
        https://github.com/Sekers/GoogleWorkspace/wiki
        
        .LINK
        Endpoint: https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
        
        .SYNOPSIS
        Google Workspace Admin - Returns user profile information via the Google Workspace Admin SDK Directory API.

        .DESCRIPTION
        Google Workspace Admin - Returns user profile information via the Google Workspace Admin SDK Directory API.
        
        Filter by User ID(s) or Domain.

        Scope suggested: https://www.googleapis.com/auth/admin.directory.user.readonly
        Note that non-admin users can use this scope as well
        (A non-admin user can make a 'users.get' or 'users.list' request with the viewType parameter
        equal to 'domain_public' to retrieve a user's public profile.)

        .PARAMETER IDs
        Comma-delimited identifier of the Google user IDs you want profile information for.
        .PARAMETER domain
        Specify Google domain to retreive all users from. The system returns a list of users in the alphabetical order of the user's email address.
        .PARAMETER ResponseLimit
        When using the 'domain' parameter, optionally limit the number of responses.

        .EXAMPLE
        Get-GoogleAdminUser -IDs 'john.doe@mydomain.com'
        .EXAMPLE
        Get-GoogleAdminUser -domain 'mydomain.com'
        .EXAMPLE
        Get-GoogleAdminUser -domain 'mydomain.com' -ResponseLimit 300

    #>

function Get-GoogleAdminUser
{ 
    [cmdletbinding()]
    param(

        [parameter(
        Position=0,
        ParameterSetName = 'ByID',
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$IDs, # Array as we loop through submitted IDs

        [parameter(
        ParameterSetName = 'ByDomain',
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$domain,
        
        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [int]$pageSize,
        
        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$pageToken,

        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [int]$ResponseLimit
    )

    # Set the endpoints
    $endpoint = 'https://admin.googleapis.com/admin/directory/v1/users/'

    # Set the response field
    $ResponseField = "users"

    # Set the parameters
    $parameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
    foreach ($parameter in $PSBoundParameters.GetEnumerator())
    {
        $parameters.Add($parameter.Key,$parameter.Value) 
    }

    # Remove the $IDs & $ResponseLimit parameters since we don't pass them on in with the other parameters
    $parameters.Remove('IDs') | Out-Null
    $parameters.Remove('ResponseLimit') | Out-Null

    if ($IDs)
    {
        # Get data for one or more IDs
        foreach ($id in $IDs)
        {
            $response = Get-UnpagedEntity -uid $id -url $endpoint
            $response
        }
    }
    else
    {
        $response = Get-PagedEntity -uid $id -url $endpoint -params $parameters -response_field $ResponseField -response_limit $ResponseLimit
        $response
    }
}
