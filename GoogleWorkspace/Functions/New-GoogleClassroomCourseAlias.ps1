# https://developers.google.com/classroom/reference/rest/v1/courses.aliases/create
# Creates one or more aliases for a course.

# Parameter,Required,Type,Description
# courseId,yes,string,Identifier for this course assigned by Classroom.When creating a course, you may optionally set this identifier to an alias string in the request to create a corresponding alias. The id is still assigned by Classroom and cannot be updated after the course is created.
# aliases,yes,string,
# --We recommend that anytime you create a course from an SIS or link a course to an SIS, that the SIS’s courseID is used as the course alias.
# --Note, that if you do an alias, you need to precede it with the identifier d: or p: (e.g., d:school_math_101). See https://developers.google.com/classroom/guides/manage-aliases

function New-GoogleClassroomCourseAlias
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
        [string[]]$aliases # Array as we loop through submitted IDs
    )

    # Set the endpoints
    $endpoint = 'https://classroom.googleapis.com/v1/courses/'
    $endUrl = '/aliases'
    
    # Create one or more aliases for a course
    foreach ($alias in $aliases)
    {
        # Set the alias into the parameter
        $parameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        $parameters.Add("alias",$alias) 


        $response = Submit-Entity -uid $courseId -url $endpoint -endUrl $endUrl -params $parameters
        $response
    }
}