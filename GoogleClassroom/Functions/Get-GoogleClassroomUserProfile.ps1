# https://developers.google.com/classroom/reference/rest/v1/userProfiles/get
# Returns one or more user profiles.

# Parameter,Required,Type,Description
# User_IDs,yes,string,Comma delimited list of user IDs for each user you want returned. It can be any one of the following:
# --the numeric identifier for the user
# --the email address of the user
# --the string literal "me", indicating the requesting user

function Get-GoogleClassroomUserProfile
{
    [cmdletbinding()]
    Param(
        [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$User_IDs # Array as we loop through submitted IDs
    )

    # Set the endpoints
    $endpoint = 'https://classroom.googleapis.com/v1/userProfiles/'

    # Get data for one or more IDs
    foreach ($user_id in $User_IDs)
    {
        $response = Get-UnpagedEntity -uid $user_id -url $endpoint
        $response
    }
}