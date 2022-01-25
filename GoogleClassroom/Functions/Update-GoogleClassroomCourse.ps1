# https://developers.google.com/classroom/reference/rest/v1/courses/patch
# Updates one or more fields in a course.

# Parameter,Required,Type,Description
# CourseIDs,yes,string,Identifier for this course assigned by Classroom.When creating a course, you may optionally set this identifier to an alias string in the request to create a corresponding alias. The id is still assigned by Classroom and cannot be updated after the course is created.
# --We recommend that anytime you create a course from an SIS or link a course to an SIS, that the SIS’s courseID is used as the course alias.
# --Note, that if you do an alias, you need to precede it with the identifier d: or p: (e.g., d:school_math_101). See https://developers.google.com/classroom/guides/manage-aliases
# name,yes,string,Name of the course. For example, "10th Grade Biology". The name is required. It must be between 1 and 750 characters and a valid UTF-8 string.
# section,no,string,Section of the course. For example, "Period 2". If set, this field must be a valid UTF-8 string and no longer than 2800 characters.
# descriptionHeading,no,string,Optional heading for the description. For example, "Welcome to 10th Grade Biology." If set, this field must be a valid UTF-8 string and no longer than 3600 characters.
# description,no,string,Optional description. For example, "We'll be learning about the structure of living creatures from a combination of textbooks, guest lectures, and lab work. Expect to be excited!" If set, this field must be a valid UTF-8 string and no longer than 30,000 characters.
# room,no,string,Optional room location. For example, "301". If set, this field must be a valid UTF-8 string and no longer than 650 characters.
# ownerId,yes,string,The identifier of the owner of a course. The identifier can be one of the following: (1) the numeric identifier for the user, (2)the email address of the user, or (3) the string literal "me".
# courseState,no,enum,State of the course. If unspecified, the default state is PROVISIONED.

function Update-GoogleClassroomCourse
{ 
    [cmdletbinding()]
    param(

        [parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string[]]$CourseIDs, # Array so we can loop

        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$name,

        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$section,

        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$descriptionHeading,
        
        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$description,

        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$room,

        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [string]$ownerId,      
                    
        [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
        [CourseState]$courseState
    )

    # Set the endpoints
    $endpoint = 'https://classroom.googleapis.com/v1/courses/'

    # Set the parameters
    $parameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
    foreach ($parameter in $PSBoundParameters.GetEnumerator())
    {
        $parameters.Add($parameter.Key,$parameter.Value) 
    }

    # Remove the $CourseIDs parameter since we don't pass that on in with the other parameters
    $parameters.Remove('CourseIDs') | Out-Null

    # Get data for one or more IDs
    foreach ($CourseID in $CourseIDs)
    {
        $response = Update-Entity -uid $CourseID -url $endpoint -params $parameters
        $response
    }
}