## ASP.NET Core Identity for Authentication and Authorization

![.NET Core](https://img.shields.io/badge/.NET%20Core-v.7-purple)
![EF Core](https://img.shields.io/badge/EF%20Core-v.7-cyan)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-v.14-drakblue)

## Table of content

- [Introduction](#introduction)
- [Technologies](#technologies)
- [Installation](#installation)
- [Getting started](#getting-started)

## Introduction
This is an ASP.NET Core Identity for Authentication and Authorization built with MVC.
This project aims to understand how identity management in C# works with roles, claims, and policy. In the real world, user management is important and required.

## Technologies
+ PostgreSQL
+ ASP .NET Core,
+ Model View Controller (MVC)
+ Entity Framework Core
+ QR Code
+ toaster
+ mailjet.com

## Installation

- Steps to perform the installation for the `mvc`
    + Register the database server with PostgreSQL
    + Check your local machine for .NET Core compatibility from microsoft webiste
    + Create an `appsettings.json` file in to main root like [example.json file](/example.json)
    + Perform these following commands
        1. dotnet restore
        2. dotnet build
        3. dotnet run
    + For database migration
        1. dotnet ef migrations  add [added new name here]
        2. dotnet ef database update
- Step 2:
    + email service
        + https://www.mailjet.com/
    + confirmation email with Facebook
        +  https://developers.facebook.com/
    + toaster
        + https://codeseven.github.io/toastr/demo.html
        + https://github.com/CodeSeven/toastr

## Getting started

- Users have to register and login in before they could be able to get total access to all the functionality.


![Fron](/img2/front.png)

### Diffrent roles for different users

![Roles](/img2/Userroles.png)

### Register form 

![Register](/img2/Registration.png)



### Login form 

+ Users can log in with two authentication factors.
+ When the user is locked, that user can never get access to some important pages. Also, in some cases, roles are managed by SuperAdmin and Admin.

![Login](/img2/Login.png)

### Roles 

+ When the user is locked, that user can never get access to some important pages. Also, in some cases, roles are managed by SuperAdmin and Admin.

![claim](/img2/Claim.png)


![Permission](/img2/Permisson.png)


### Two Authentication Factor
+ REST API
    + https://localhost:7162/Account/EnableAuthenticator

![Authentication](/img2/Authentication.png)


### Access Denied

If an unauthorized user clicks on the page, that user will get access denied.

![Denied](/img2/Denied.png)

