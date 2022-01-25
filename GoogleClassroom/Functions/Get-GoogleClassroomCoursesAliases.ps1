# https://developers.google.com/classroom/reference/rest/v1/courses.aliases/list
# Returns a list of aliases for one or more courses.

# Parameter,Required,Type,Description
# CourseIDs,yes,string,Comma-delimited identifier of the courses to return aliases for. This identifier can be either the Classroom-assigned identifier or an alias.

function Get-GoogleClassroomCoursesAliases
{ 
    [cmdletbinding()]
    param(

        [parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$CourseIDs # Array as we loop through submitted CourseIDs
    )

    # Set the endpoints
    $endpoint = 'https://classroom.googleapis.com/v1/courses/'
    $endUrl = '/aliases'

    # Get data for one or more IDs
    foreach ($courseId in $CourseIDs)
    {
        $response = Get-UnpagedEntity -uid $courseId -url $endpoint -endUrl $endUrl
        $response
    }
}
