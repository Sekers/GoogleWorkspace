# https://developers.google.com/classroom/reference/rest/v1/courses.teachers/list
# Returns a list of teachers of one or more courses that the requester is permitted to view.

# Parameter,Required,Type,Description
# CourseIDs,yes,string,Comma-delimited identifier of the courses to return aliases for. This identifier can be either the Classroom-assigned identifier or an alias.
# pageSize,no,integer,Maximum number of items to return (per page). The default is 30 if unspecified or 0. The server may return fewer than the specified number of results.
# pageToken,no,string,nextPageToken value returned from a previous list call, indicating that the subsequent page of results should be returned.
# ResponseLimit,no,Limits response to this number of results.

function Get-GoogleClassroomCoursesTeachersList
{ 
    [cmdletbinding()]
    param(

        [parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$CourseIDs, # Array as we loop through submitted CourseIDs

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
    $endpoint = 'https://classroom.googleapis.com/v1/courses/'
    $endUrl = '/teachers'

    # Set the response field
    $ResponseField = "teachers"

    # Set the parameters
    $parameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
    foreach ($parameter in $PSBoundParameters.GetEnumerator())
    {
        $parameters.Add($parameter.Key,$parameter.Value) 
    }

    # Remove the $CourseIDs & $ResponseLimit parameters since we don't pass them on in with the other parameters
    $parameters.Remove('CourseIDs') | Out-Null
    $parameters.Remove('ResponseLimit') | Out-Null

    # Get data for one or more IDs
    foreach ($courseId in $CourseIDs)
    {
        $response = Get-PagedEntity -uid $courseId -url $endpoint -endUrl $endUrl -params $parameters -response_field $ResponseField -response_limit $ResponseLimit
        $response
    }
}
