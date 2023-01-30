# https://developers.google.com/classroom/reference/rest/v1/courses/list
# Returns a list of courses that the requesting user is permitted to view, restricted to those that match the request.
# Returned courses are ordered by creation time, with the most recently created coming first.

# Parameter,Required,Type,Description
# studentId,no,string,Restricts returned courses to those having a student with the specified identifier.
# teacherId,no,string,Restricts returned courses to those having a teacher with the specified identifier.
# courseState,no,enum array,Restricts returned courses to those in one of the specified states The default value is ACTIVE, ARCHIVED, PROVISIONED, DECLINED.
# pageSize,no,integer,Maximum number of items to return (per page). Zero or unspecified indicates that the server may assign a maximum.
# pageToken,no,string,nextPageToken value returned from a previous list call, indicating that the subsequent page of results should be returned.
# ResponseLimit,no,Limits response to this number of results.

function Get-GoogleClassroomCoursesList
{ 
    [cmdletbinding()]
    param(

        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$studentId,

        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$teacherId,

        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [CourseState[]]$courseStates, # Array as we loop through submitted IDs

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
    $endpoint = 'https://classroom.googleapis.com/v1/courses'

    # Set the response field
    $ResponseField = "courses"

    # Set the parameters
    $parameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
    foreach ($parameter in $PSBoundParameters.GetEnumerator())
    {
        $parameters.Add($parameter.Key,$parameter.Value) 
    }

    # Remove the $ResponseLimit parameter since we don't pass that on in with the other parameters
    $parameters.Remove('ResponseLimit') | Out-Null

    # Clear out the courseStates parameter and add each one in separately because that's how Google does it...
    $parameters.Remove('courseStates') | Out-Null
    foreach ($courseState in $courseStates)
    {
        $parameters.Add('courseStates',$courseState) 
    } 

    $response = Get-PagedEntity -url $endpoint -params $parameters -response_field $ResponseField -response_limit $ResponseLimit
    $response 
}
