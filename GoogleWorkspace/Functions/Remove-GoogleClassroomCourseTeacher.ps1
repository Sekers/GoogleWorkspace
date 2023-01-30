# https://developers.google.com/classroom/reference/rest/v1/courses.teachers/delete
# Removes one or more teachers from a course.

# Parameter,Required,Type,Description
# courseId,yes,string,Identifier of the course to create the student in. This identifier can be either the Classroom-assigned identifier or an alias.
# userIds,yes,string,Comma delimited list of user IDs for each teacher you want added to the course. It can be any one of the following:
# --the numeric identifier for the user
# --the email address of the user
# --the string literal "me", indicating the requesting user

function Remove-GoogleClassroomCourseTeacher
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
    
    # Create one or more aliases for a course
    foreach ($userId in $userIds)
    {
        $endUrl = '/teachers'
        $endUrl += '/' + $userId

        $response = Remove-Entity -uid $courseId -url $endpoint -endUrl $endUrl 
        $response
    }
}