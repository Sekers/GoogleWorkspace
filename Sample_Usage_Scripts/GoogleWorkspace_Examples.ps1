# Sample Google Workspace PowerShell Module Usage Script

<#
    Import the Module
#>
# Import-Module GoogleWorkspace
# Import-Module "$PSScriptRoot\..\GoogleWorkspace\GoogleWorkspace.psm1"

<#
    Retrieve the Google Workspace Module Configuration File
#>
# Get-GoogleWorkspaceConfig -ConfigPath '.\Sample_Usage_Scripts\Config\google_workspace_api_config.json'

<#
    Set the Necessary File Paths.
    Both These *MUST* Be Set Prior to Running Commands.
#>
# Set-GoogleWorkspaceConfigFilePath -Path "$PSScriptRoot\Config\google_workspace_api_config.json" # The location where you placed the credentials file you downloaded from the Google developer console.
# Set-GoogleWorkspaceTokensFilePath -Path "$env:USERPROFILE\API_Tokens\myapp_google_workspace_key.json" # The location where you want the encrypted access and refresh tokens to be stored.

<#
    Optionally, Test Connecting to the Google Workspace API Service.
    Optional Parameters Can Force Reauthentication or Token Refresh.
#>
# Connect-GoogleWorkspace
# Connect-GoogleWorkspace -ForceReauthentication
# Connect-GoogleWorkspace -ForceRefresh

<#
    Get-GoogleClassroomCoursesList Example
#>
# $ActiveCourses = Get-GoogleClassroomCoursesList -courseStates ACTIVE | Sort-Object name
# $OtherCourses = Get-GoogleClassroomCoursesList -courseStates ARCHIVED, PROVISIONED, DECLINED, SUSPENDED
# Write-Host "Total Active Courses Count:" $ActiveCourses.Count
# Get-GoogleClassroomCoursesList -ResponseLimit 5
# Get-GoogleClassroomCoursesList | Where-Object name -Like "test"
# Get-GoogleClassroomCoursesList -courseStates 'ACTIVE' | Where-Object {$_.name -match "visual art"} |  Sort-Object name
# Get-GoogleClassroomCoursesList -courseStates 'ACTIVE' | Where-Object {$_.section -match "7EBx"} |  Sort-Object name
# Get-GoogleClassroomCoursesList -courseStates 'ACTIVE' | Where-Object {$_.ownerId -eq "123456789101112131415"} |  Sort-Object name
# Get-GoogleClassroomCoursesList -teacherId "teacher@school.edu"
# Get-GoogleClassroomCoursesList -studentId "child@school.edu"
# Get-GoogleClassroomCoursesList -teacherId "teacher@school.edu" -studentId "child@school.edu"

<#
    Get-GoogleClassroomUserProfile Example
    Suggest returning to an array because the .Count" function will otherwise not work if you hav less than 2 responses.
#>
# [array]$UserProfiles = Get-GoogleClassroomUserProfile -User_IDs "user@school.edu", "me", 123456789101112131415
# $UserProfiles.Count

<#
    Get-GoogleClassroomCourse Example
#>
# Get-GoogleClassroomCourse -IDs 12345678910, 987654321098

<#
    Get-GoogleClassroomCoursesAliases Example
#>
# $Aliases = Get-GoogleClassroomCoursesAliases -CourseIDs "12345678910", "d:2020-2021_4TD"

<#
    Get-GoogleClassroomCoursesTeachersList Example
#>
# Get-GoogleClassroomCoursesTeachersList -CourseIDs 12345678910
# $CourseTeachers = Get-GoogleClassroomCoursesTeachersList -CourseIDs "12345678910", "987654321098", '67891012345', "d:2020-2021_4TD"
# $CourseTeachersIDs = Get-GoogleClassroomCoursesTeachersList -CourseIDs "12345678910", "987654321098", '67891012345', "d:2020-2021_4TD" | Select-Object -Property userId
# foreach ($Teacher in $CourseTeachers)
# {
#     Get-GoogleClassroomUserProfile -User_IDs $Teacher.userId | Select-Object -ExpandProperty name | Select-Object -ExpandProperty fullName
# }

<#
    Get-GoogleClassroomCoursesStudentsList Example
#>
# $Students = Get-GoogleClassroomCoursesStudentsList -CourseIDs "d:2020-2021_4TD"

<#
    New-GoogleClassroomCourseAlias Example
#>
# New-GoogleClassroomCourseAlias -courseId "12345678910" -aliases "d:testalias1", "d:testalias2"

<#
    New-GoogleClassroomCourse Example
    When creating a course, you may optionally set the "id" parameter to an alias string in the request to create a corresponding alias.
#>
# New-GoogleClassroomCourse -name "English 5" -section "5EA" -descriptionHeading "Heading Text" -description "Description Text" -room "Room1" -ownerId 'teacher@school.edu' -courseState ACTIVE 
# New-GoogleClassroomCourse -id "d:2020-2021_4TD" -name "English 5" -section "5EA" -descriptionHeading "Heading Text" -description "Description Text" -room "Room1" -ownerId 'teacher@school.edu' -courseState ACTIVE 

<#
    New-GoogleClassroomCourseStudent Example
#>
# New-GoogleClassroomCourseStudent -courseId "d:2020-2021_4TD" -userIds "child@school.edu"

<#
    Remove-GoogleClassroomCourse Example
#>
# Remove-GoogleClassroomCourse -IDs 12345678910, 987654321098

<#
    Update-GoogleClassroomCourse Example
#>
# Update-GoogleClassroomCourse -CourseIDs "12345678910" -ownerId "123456789101112131415"
# Update-GoogleClassroomCourse -CourseIDs "12345678910", "d:2020-2021_4TD" -courseState ARCHIVED
# Update-GoogleClassroomCourse -CourseIDs "d:2020-2021_4TD" -name "Visual Art - Grade 4" -section "Section Name" -descriptionHeading "Heading Text" -description "Description Text" -room "Room1"

<#
    New-GoogleClassroomCourseTeacher Example
#>
# New-GoogleClassroomCourseTeacher -courseId "12345678910" -userIds "teacher@school.edu", "123456789101112131415"

<#
    Remove-GoogleClassroomCourseTeacher Example
#>
# Remove-GoogleClassroomCourseTeacher -courseId "12345678910" -userIds "teacher@school.edu", "123456789101112131415"
