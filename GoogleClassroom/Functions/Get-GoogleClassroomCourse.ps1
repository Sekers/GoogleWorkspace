# https://developers.google.com/classroom/reference/rest/v1/courses/get
# Returns courses.

# Parameter,Required,Type,Description
# IDs,yes,string,Comma-delimited identifier of the courses to return. This identifier can be either the Classroom-assigned identifier or an alias.

function Get-GoogleClassroomCourse
{ 
    [cmdletbinding()]
    param(

        [parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$IDs # Array as we loop through submitted IDs
    )

    # Set the endpoints
    $endpoint = 'https://classroom.googleapis.com/v1/courses/'

    # Get data for one or more IDs
    foreach ($id in $IDs)
    {
        $response = Get-UnpagedEntity -uid $id -url $endpoint
        $response
    }
}
