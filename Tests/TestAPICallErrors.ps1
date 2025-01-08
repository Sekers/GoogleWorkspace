# CODE FOR TESTING Google Workspace API RATE LIMITING

$ErrorActionPreference = "Stop"

# Import the module
# Normally this module would be installed and your command would simply be:
# Import-Module GoogleWorkspace
Import-Module "$PSScriptRoot\..\GoogleWorkspace\GoogleWorkspace.psm1" -Force # Force reimports an updated module.

# Set Paths
Set-GoogleWorkspaceConfigFilePath -Path "$PSScriptRoot\..\@Local Only\Config\config_google_workspace_api.json"
Set-GoogleWorkspaceTokensFilePath -Path "$env:USERPROFILE\API_Tokens\moduletesting_google_workspace_key.json"

# Set Google WorkSpace Needed Scopes
$Scopes = @(
'https://www.googleapis.com/auth/admin.directory.user.readonly' # Admin SDK API: See info about users on your domain. (For Get-GoogleAdminUser to get a list of Google IDs.)
'https://www.googleapis.com/auth/classroom.courses' # Google Classroom API: See, edit, create, and permanently delete your Google Classroom classes.
'https://www.googleapis.com/auth/classroom.rosters' # Google Classroom API: Manage your Google Classroom class rosters.
'https://www.googleapis.com/auth/classroom.guardianlinks.students' # Google Classroom API: View and manage guardians for students in your Google Classroom classes.
)
Set-GoogleWorkspaceScopes -Scopes $Scopes

# Connect to Google Workspace SKY API
Connect-GoogleWorkspace

do{
    # Get Courses
    [array]$GoogleClassroom_CourseList = Get-GoogleClassroomCoursesList

    # Unpaged Test
    [array]$GoogleClassroom_CourseAliases = Get-GoogleClassroomCoursesAliases -CourseIDs $GoogleClassroom_CourseList.id # | Where-Object {$null -ne $_.aliases} | Select-Object -ExpandProperty aliases

    # Paged Test
    # [array]$list = Get-GoogleClassroomCoursesStudentsList -CourseIDs $($GoogleClassroom_CourseList.id)[0..200]
}
while (1 -eq 1)
