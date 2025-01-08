# Changelog for Google Workspace PowerShell Module

## [0.3.2](https://github.com/Sekers/GoogleWorkspace/tree/0.3.2) - (2025-01-08)

### Fixes

- Increase sleep time when hitting Google Workspace API limit (it was too short before as Google has a per-minute limit on most endpoints).

### Other

- Added 'Set-GoogleWorkspaceScopes' to the example commands listing.

## [0.3.1](https://github.com/Sekers/GoogleWorkspace/tree/0.3.1) - (2023-01-31)

### Fixes

- Adjusted Get-GoogleAdminUser so that it takes EITHER 'IDs' or 'domain' and not both at the same time.
- Publicly exported Set-GoogleWorkspaceScopes.

### Other

- Removed the 'Prerelease' tag from the module to more easily install it from the PowerShell Gallery.

## [0.3.0](https://github.com/Sekers/GoogleWorkspace/tree/0.3.0) - (2023-01-30)

### Features

- Enlarge module focus from the Google Classroom API to the Google Workspace API.
- First release to PowerShell Gallery

## [0.2.0](https://github.com/Sekers/GoogleWorkspace/tree/0.2.0) - (2023-01-24)

### Features

- Changed the [deprecated Google API OAuth out-of-band](https://developers.googleblog.com/2022/02/making-oauth-flows-safer.html) flow to the [loopback](https://developers.google.com/identity/protocols/oauth2/native-app#redirect-uri_loopback) method.

## [0.1.0](https://github.com/Sekers/GoogleWorkspace/tree/0.1.0) - (2022-01-22)

### Features

- Initial public release

Author: [**@Sekers**](https://github.com/Sekers)
