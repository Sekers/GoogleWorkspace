# https://developers.google.com/classroom/reference/rest/v1/courses.teachers/create
# Adds one or more teachers to a course.

# Parameter,Required,Type,Description
# courseId,yes,string,Identifier of the course to create the student in. This identifier can be either the Classroom-assigned identifier or an alias.
# userIds,yes,string,Comma delimited list of user IDs for each teacher you want added to the course. It can be any one of the following:
# --the numeric identifier for the user
# --the email address of the user
# --the string literal "me", indicating the requesting user

function New-GoogleClassroomCourseTeacher
{ 
    [cmdletbinding()]
    param(

        [parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$courseId,

        [parameter(
        Position=1,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$userIds # Array as we loop through submitted IDs
    )

    # Set the endpoints
    $endpoint = 'https://classroom.googleapis.com/v1/courses/'
    $endUrl = '/teachers'
    
    # Create one or more aliases for a course
    foreach ($userId in $userIds)
    {
        # Set the userId into the parameter
        $parameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $parameters.Add("userId",$userId)

        $response = Submit-Entity -uid $courseId -url $endpoint -endUrl $endUrl -params $parameters
        $response
    }
}