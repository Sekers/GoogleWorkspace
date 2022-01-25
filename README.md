# SKYAPI PowerShell Module <!-- omit in toc -->

## Table of Contents  <!-- omit in toc -->

- [Overview](#overview)
- [What's New](#whats-new)
- [Current API Support](#current-api-support)
- [Documentation](#documentation)
- [Developing and Contributing](#developing-and-contributing)

---

## Overview

PowerShell Module for the [Google Classroom API](https://developers.google.com/classroom).

---

## What's New

See [CHANGELOG.md](./CHANGELOG.md) for information on the latest updates, as well as past releases.

---

## Current API Support

At present, this module is focused on creating, removing and updating Google Classroom classes as well as teacher and student rostering. However, it has been built so that other Google Classroom API endpoints can easily be added in.

Future releases will add support for course work & materials, guardians, and invitations/registrations.

See the [GoogleClassroomAPI Wiki](https://github.com/Sekers/GoogleClassroomAPI/wiki) for a list of the [endpoints currently supported](https://github.com/Sekers/GoogleClassroomAPI/wiki#api-endpoints).

---

## Documentation

The SKYAPI module documentation is hosted in the [GoogleClassroomAPI Wiki](https://github.com/Sekers/GoogleClassroomAPI/wiki). Examples are included in the [Sample Usage Scripts folder](./Sample_Usage_Scripts).

---

## Developing and Contributing

Contact us on the [Grimadmin.com GoogleClassroomAPI PowerShell Module Forum](https://www.grimadmin.com/forum/index.php?forum=8) if you would like to contribute.

This project is developed using a [simplified Gitflow workflow](https://www.grimadmin.com/article.php/simple-modified-gitflow-workflow) that cuts out the release branches, which are unnecessary when maintaining only a single version for production. The Master/Main branch will always be the latest stable version released and tagged with an updated version number anytime the Develop branch is merged into it. [Rebasing](https://www.atlassian.com/git/tutorials/merging-vs-rebasing) will occur if we need to streamline complex history.

You are also welcome to [fork](https://guides.github.com/activities/forking/) the project and then offer your changes back using a [pull request](https://guides.github.com/activities/forking/#making-a-pull-request).
