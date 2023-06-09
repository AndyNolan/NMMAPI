# NMMAPI - A PowerShell Module for NMM (Nerdio Manager for MSP)

![Image](https://img.shields.io/badge/PowerShell%205.1%20&%207.3-Ready-blue.svg?color=5391FE&style=flat&logo=powershell)

## About NMMAPI

The NMMAPI PowerShell module is a collection of cmdlets built to interact with the [Nerdio Manager for MSP](https://getnerdio.com/nerdio-manager-for-msp/) REST API.

The goal of this module is to empower NMM admins to get more out of their install with simple PowerShell functions.

This repository, along with the PowerShell Gallery packages, will continue to be maintained as long as Nerdio keeps releasing REST API endpoints!

Not all endpoints are included in this module yet - mostly due to the large list of variables needed for some of the functions. Over time I will get to these, and encourage the community to contribute, if folks wish to!

At the bottom of this README.md is a [full list of functions](#command-legend--documentation) along with their implementation status, and some simple documentation for a few commands.

***

## Installation

This module can be installed from the PowerShell Gallery with the following command in PowerShell 5.1+

```powershell
Install-Module -Name NMMAPI
```

After installation, load the module into your PowerShell session:

```powershell
Import-Module -Name NMMAPI
```

## Keeping NMMAPI up to date

You can update your module to the latest available release on PowerShell Gallery by running the following command;

```powershell
Update-Module -Name NMMAPI
```

Alternatively, you can download the module via this Github repository and drop the module folder into your PowerShell modules directory.

***

## Enabling the REST API in NMM

Ensure that your NMM installation configuration has the `REST API` enabled.

* Browse to your NMM installation, navigate to `Settings` and then to `Integrations` - the `REST API` section will have a `Current Status: Disabled` field.<!-- ![Image](./screenshots/nav_settings_integrations.png) ![Image](./screenshots/rest_api_enable.png) -->
* Click on `Disabled`, and the `Enable REST API` dialog will open. The first step will be to create the `API client` - click on the `Run` button, it will take a few seconds to generate the client.<!-- ![Image](./screenshots/rest_api_dialog_1.png) -->
* Grant `Admin Consent` by clicking on the `Grant` button - a new window will pop up with the `NMM App Registration` in the Azure portal. You will need to click the `Grant consent for <tenant>` button, and then click `Yes` in the dialog to confirm consent.<!-- ![Image](./screenshots/rest_api_dialog_3.png) -->
* Navigate back to the `NMM` tab and hit the refresh icon next to the `Grant` button.<!-- ![Image](./screenshots/rest_api_dialog_2.png) -->
* Generate the `Client Secret`, by clicking the `Generate` button.<!-- ![Image](./screenshots/rest_api_dialog_4.png) -->
* You will be presented with all the critical information needed to connect to the `NMM REST API`.<!-- ![Image](./screenshots/rest_api_dialog_5.png) -->

    >Be sure to secure your `Client Secret`; it will not be displayed again. However, it can be regenerated at any time.

***

## Setting up the module

* Once imported (`Import-Module -Name NMMAPI`), run the following command:

```powershell
Add-NMMCredentials
```

* You will be prompted to enter your `NMM URL`, `OAuth 2.0 token`, `M365 Tenant ID`, `NMM Client ID`, `NMM Application Scope` and your `NMM Application Secret` that were created during the enablement of the `REST API`. If you need to retrieve the settings again, they are available on the `Settings -> Integration` page of your NMM installation.
* After adding your NMM credentials, the cmdlet will attempt to get a response from the `/rest-api/v1/test` endpoint, and respond with a success confirmation.
* For frequent use and portability, there is the `Export-NMMCredentials` and `Import-NMMCredentials` cmdlets that will save your settings to `C:\Users\<username>\NMMAPI\nmmConfig.json` for later use.
    >You should treat this file with the importance it deserves; it is your API key!

***

## Using the module

* Once `Add-NMMCredentials` has been executed, and you've received a successful response from the test API endpoint, you're ready to go!
* Run `Get-NMMCustomers` to get a list of accounts that are configured in your NMM installation.
  * From here you can see your organizations organized by `ID` and by `Name`.
  * `ID` will be used to identify which customer account(s) are being targeted by almost all cmdlets that are included in this module.

### Example - *Setting a secure variable for a customer*

It can be useful to leverage secure variables when you have a scripted action that installs software or performs other tasks that require a customer-unique variable. This feature allows you to maintain generalized scripts and only manage the customer secure variables.

In this example, you are going to manually specify a variable to be created in a customer account.

First, find what customer you'd like to create a secure variable for:

```powershell
Get-NMMCustomers | Where-Object name -match "demo"

id name
-- ----
54 Demo Customer
```

You can see that your demo customer has the ID of "54" - so you will reference that ID when using the `New-NMMCustomerSecureVariable` cmdlet:

```powershell
New-NMMCustomerSecureVariable -id 54 -variableName NewVariable -variableValue NewValue

job
---
@{id=187416; status=Completed}
```

Now when you reference the customer log, you will see the REST API user executed the task "Create secure variable."

But wait, there's more! This cmdlet can, for example, pipe the output of your original `Get-NMMCustomers | Where-Object name -match "demo"` command right into `New-NMMCustomerSecureVariable`.

```powershell
Get-NMMCustomers | Where-Object name -match "demo" | New-NMMCustomerSecureVariable -variableName NewVariable1 -variableValue NewValue1

job
---
@{id=187417; status=Completed}
```

## Command legend & documentation

This table corresponds to the most recent REST API endpoints in Nerdio Manager for MSP, in alphabetical order, along with the PowerShell cmdlet to utilize that endpoint and whether or not this is implemented yet in the PowerShell module. Explicit documentation for each of these commands are in progress, and while most are self-explanatory, some are a little more awkward. 

**REST Method**|**PowerShell Command**|**Implemented**|**ETA**
:-----:|:-----:|:-----:|:-----:
|**Test**
GET|[Test-NMMAPI](./docs/Test-NMMAPI.md)|:white_check_mark:|
|**Account Provisioning**
POST|[Register-NMMAD](./docs/Register-NMMAD.md)|:white_check_mark:|
POST|[Register-NMMFileStorage](./docs/Register-NMMFileStorage.md)|:white_check_mark:|
POST|[Register-NMMNetwork](./docs/Register-NMMNetwork.md)|:white_check_mark:|
POST|[Register-NMMTenant](./docs/Register-NMMTenant.md)|:white_check_mark:|
|**Accounts**
GET|[Get-NMMCustomers](./docs/Get-NMMCustomers.md)|:white_check_mark:|
|**Storage Azure files**
GET|[Get-NMMAzureFilesAutoscale](./docs/Get-NMMAzureFilesAutoscale.md)|:x:|Q2
PUT|[Set-NMMAzureFilesAutoscale](./docs/Set-NMMAzureFilesAutoscale.md)|:x:|Q2
POST|[Set-NMMAzureFilesAutoscaleStatus](./docs/Set-NMMAzureFilesAutoscaleStatus.md)|:x:|Q2
|**App Role Assignments**
GET|[Get-NMMAppRoleAssignments](./docs/Get-NMMAppRoleAssignments.md)|:white_check_mark:|
GET|[Get-NMMAppRoles](./docs/Get-NMMAppRoles.md)|:white_check_mark:|
|**Authentication**|These are internal to the NMMAPI module, for authentication into NMM
N/A|[Add-NMMCredentials](./docs/Add-NMMCredentials.md)|:white_check_mark:|
N/A|[Export-NMMCredentials](./docs/Export-NMMCredentials.md)|:white_check_mark:|
GET|[Get-NMMToken](./docs/Get-NMMToken.md)|:white_check_mark:|
N/A|[Import-NMMCredentials](./docs/Import-NMMCredentials.md)|:white_check_mark:|
|**Backup**
POST|[Disable-NMMCustomerBackup](./docs/Disable-NMMCustomerBackup.md)|:white_check_mark:|
POST|[Enable-NMMCustomerBackup](./docs/Enable-NMMCustomerBackup.md)|:white_check_mark:|
GET|[Get-NMMCustomerProtectedItems](./docs/Get-NMMCustomerProtectedItems.md)|:white_check_mark:|
GET|[Get-NMMCustomerRecoveryPoints](./docs/Get-NMMCustomerRecoveryPoints.md)|:white_check_mark:|
POST|[Invoke-NMMCustomerBackup](./docs/Invoke-NMMCustomerBackup.md)|:white_check_mark:|
POST|[Invoke-NMMCustomerRestore](./docs/Invoke-NMMCustomerRestore.md)|:white_check_mark:|
|**Cost Estimator**
GET|[Get-NMMEstimate](./docs/Get-NMMEstimate.md)|:white_check_mark:|
|**Desktop Image**
GET|[Get-NMMDesktopImage](./docs/Get-NMMDesktopImage.md)|:white_check_mark:|
GET|[Get-NMMDesktopImageChangelog](./docs/Get-NMMDesktopImageChangelog.md)|:white_check_mark:|
GET|[Get-NMMDesktopImageDetail](./docs/Get-NMMDesktopImageDetail.md)|:white_check_mark:|
PUT|[Start-NMMDesktopImage](./docs/Start-NMMDesktopImage.md)|:white_check_mark:|
PUT|[Stop-NMMDesktopImage](./docs/Stop-NMMDesktopImage.md)|:white_check_mark:|
POST|[Create-NMMDesktopImageFromVM](./docs/Create-NMMDesktopImageFromVM.md)|:x:|Q2
POST|[Create-NMMDesktopImageFromLibrary](./docs/Create-NMMDesktopImageFromLibrary.md)|:x:|Q2
POST|[Clone-NMMDesktopImage](./docs/Clone-NMMDesktopImage.md)|:x:|Q2
POST|[Enable-NMMDesktopImageRDP](./docs/Enable-NMMDesktopImageRDP.md)|:x:|Q2
PUT|[Invoke-NMMDesktopSetAsImage](./docs/Invoke-NMMDesktopSetAsImage.md)|:x:|Q2
PUT|[Invoke-NMMDesktopImageScriptedAction](./docs/Invoke-NMMDesktopImageScriptedAction.md)|:x:|Q2
DELETE|[Remove-NMMDesktopImage](./docs/Remove-NMMDesktopImage.md)|:x:|Q2
DELETE|[Remove-NMMDesktopImageSchedule](./docs/Remove-NMMDesktopImageSchedule.md)|:x:|Q2
|**Directories**
GET|[Get-NMMDirectories](./docs/Get-NMMDirectories.md)|:white_check_mark:|
|**FSLogix Configs**
GET|[Get-NMMFSlogixConfig](./docs/Get-NMMFSlogixConfig.md)|:white_check_mark:|
|**Host**
DELETE|[Remove-NMMHost](./docs/Remove-NMMHost.md)|:x:|Q2
GET|[Get-NMMHosts](./docs/Get-NMMHosts.md)|:white_check_mark:|
POST|[Restart-NMMHost](./docs/Restart-NMMHost.md)|:white_check_mark:|
POST|[Start-NMMHost](./docs/Start-NMMHost.md)|:white_check_mark:|
POST|[Stop-NMMHost](./docs/Stop-NMMHost.md)|:white_check_mark:|
POST|[Create-NMMHost](./docs/Create-NMMHost.md)|:x:|Q2
POST|[Set-NMMHostDrainMode](./docs/Set-NMMHostDrainMode.md)|:x:|Q2
POST|[Invoke-NMMHostReimage](./docs/Invoke-NMMHostReimage.md)|:x:|Q2
POST|[Set-NMMHostUserAssignment](./docs/Set-NMMHostUserAssignment.md)|:x:|Q2
PUT|[Invoke-NMMHostScript](./docs/Invoke-NMMHostScript.md)|:x:|Q2
|**Host Pools**
GET|[Get-NMMHostPool](./docs/Get-NMMHostPool.md)|:white_check_mark:|
GET|[Get-NMMHostPoolAD](./docs/Get-NMMHostPoolAD.md)|:white_check_mark:|
GET|[Get-NMMHostPoolAssignedUsers](./docs/Get-NMMHostPoolAssignedUsers.md)|:white_check_mark:|
GET|[Get-NMMHostPoolAutoscale](./docs/Get-NMMHostPoolAutoscale.md)|:white_check_mark:|
GET|[Get-NMMHostPoolAVD](./docs/Get-NMMHostPoolAVD.md)|:white_check_mark:|
GET|[Get-NMMHostPoolFSLogix](./docs/Get-NMMHostPoolFSLogix.md)|:white_check_mark:|
GET|[Get-NMMHostPoolRDPSettings](./docs/Get-NMMHostPoolRDPSettings.md)|:white_check_mark:|
GET|[Get-NMMHostPoolSessionTimeouts](./docs/Get-NMMHostPoolSessionTimeouts.md)|:white_check_mark:|
GET|[Get-NMMHostPoolTags](./docs/Get-NMMHostPoolTags.md)|:white_check_mark:|
GET|[Get-NMMHostPoolVMDeployment](./docs/Get-NMMHostPoolVMDeployment.md)|:white_check_mark:|
DELETE|[Remove-NMMHostPool](./docs/Remove-NMMHostPool.md)|:x:|Q2
DELETE|[Remove-NMMHostPoolVMs](./docs/Remove-NMMHostPoolVMs.md)|:x:|Q2
DELETE|[Remove-NMMHostPoolScheduledJobs](./docs/Remove-NMMHostPoolScheduledJobs.md)|:x:|Q2
POST|[Create-NMMHostPool](./docs/Create-NMMHostPool.md)|:x:|Q2
POST|[Set-NMMHostPoolUserAssignment](./docs/Set-NMMHostPoolUserAssignment.md)|:x:|Q2
POST|[Remove-NMMHostPoolUserAssignment](./docs/Remove-NMMHostPoolUserAssignment.md)|:x:|Q2
POST|[Invoke-NMMHostPoolClone](./docs/Invoke-NMMHostPoolClone.md)|:x:|Q2
POST|[Stop-NMMHostPoolAllHosts](./docs/Stop-NMMHostPoolAllHosts.md)|:x:|Q2
POST|[Start-NMMHostPoolAllHosts](./docs/Start-NMMHostPoolAllHosts.md)|:x:|Q2
POST|[Restart-NMMHostPoolAllHosts](./docs/Restart-NMMHostPoolAllHosts.md)|:x:|Q2
POST|[Invoke-NMMHostPoolBulkReimage](./docs/Invoke-NMMHostPoolBulkReimage.md)|:x:|Q2
POST|[Invoke-NMMHostPoolBulkDrain](./docs/Invoke-NMMHostPoolBulkDrain.md)|:x:|Q2
POST|[Invoke-NMMHostPoolBulkScripts](./docs/Invoke-NMMHostPoolBulkScripts.md)|:x:|Q2
PUT|[Set-NMMHostPoolAutoscale](./docs/Set-NMMHostPoolAutoscale.md)|:x:|Q2
PUT|[Set-NMMHostPoolCapacityExtenderConfig](./docs/Set-NMMHostPoolCapacityExtenderConfig.md)|:x:|Q2
PUT|[Invoke-NMMHostPoolBulkLogoff](./docs/Invoke-NMMHostPoolBulkLogoff.md)|:x:|Q2
PUT|[Invoke-NMMHostPoolBulkDisconnect](./docs/Invoke-NMMHostPoolBulkDisconnect.md)|:x:|Q2
PUT|[Invoke-NMMHostPoolBulkMessage](./docs/Invoke-NMMHostPoolBulkMessage.md)|:x:|Q2
|**Invoices**
GET|[Get-NMMInvoiceID](./docs/Get-NMMInvoiceID.md)|:white_check_mark:|
GET|[Get-NMMInvoices](./docs/Get-NMMInvoices.md)|:white_check_mark:|
GET|[Get-NMMInvoicesPaid](./docs/Get-NMMInvoicesPaid.md)|:white_check_mark:|
GET|[Get-NMMInvoicesUnpaid](./docs/Get-NMMInvoicesUnpaid.md)|:white_check_mark:|
|**Jobs**
GET|[Get-NMMJob](./docs/Get-NMMJob.md)|:white_check_mark:|
GET|[Get-NMMJobTasks](./docs/Get-NMMJobTasks.md)|:white_check_mark:|
POST|[Restart-NMMJob](./docs/Restart-NMMJob.md)|:white_check_mark:|
|**Networks**
GET|[Get-NMMAllNetworks](./docs/Get-NMMAllNetworks.md)|:white_check_mark:|
GET|[Get-NMMManagedNetworks](./docs/Get-NMMManagedNetworks.md)|:white_check_mark:|
POST|[Register-NMMNetwork](./docs/Register-NMMNetwork.md)|:white_check_mark:|
|**Recovery Vault**
GET|[Get-NMMAllRecoveryVaults](./docs/Get-NMMAllRecoveryVaults.md)|:white_check_mark:|
GET|[Get-NMMLinkedRecoveryVaults](./docs/Get-NMMLinkedRecoveryVaults.md)|:white_check_mark:|
GET|[Get-NMMRecoveryVaultPolicies](./docs/Get-NMMRecoveryVaultPolicies.md)|:white_check_mark:|
GET|[Get-NMMRecoveryVaultPoliciesByRegion](./docs/Get-NMMRecoveryVaultPoliciesByRegion.md)|:white_check_mark:|
GET|[Get-NMMRecoveryVaultPolicy](./docs/Get-NMMRecoveryVaultPolicy.md)|:white_check_mark:|
POST|[New-NMMRecoveryVault](./docs/New-NMMRecoveryVault.md)|:white_check_mark:|
POST|[New-NMMRecoveryVaultPolicy](./docs/New-NMMRecoveryVaultPolicy.md)|:x:|Q3
POST|[Register-NMMRecoveryVault](./docs/Register-NMMRecoveryVault.md)|:white_check_mark:|
POST|[Set-NMMRerecoveryVaultPolicyResources](./docs/Set-NMMRerecoveryVaultPolicyResources.md)|:x:|Q3
DELETE|[Remove-NMMRecoveryVaultPolicy](./docs/Remove-NMMRecoveryVaultPolicy.md)|:white_check_mark:|
POST|[Unregister-NMMRecoveryVault](./docs/Unregister-NMMRecoveryVault.md)|:white_check_mark:|
|**Reservations**
GET|[Get-NMMReservationId](./docs/Get-NMMReservationId.md)|:white_check_mark:|
GET|[Get-NMMReservationIdResources](./docs/Get-NMMReservationIdResources.md)|:white_check_mark:|
GET|[Get-NMMReservations](./docs/Get-NMMReservations.md)|:white_check_mark:|
POST|[New-NMMReservation](./docs/New-NMMReservation.md)|:white_check_mark:|
DELETE|[Remove-NMMReservation](./docs/Remove-NMMReservation.md)|:white_check_mark:|
POST|[Set-NMMReservation](./docs/Set-NMMReservation.md)|:white_check_mark:|
|**Resource Group**
GET|[Get-NMMResourceGroup](./docs/Get-NMMResourceGroup.md)|:white_check_mark:|
POST|[Register-NMMResourceGroup](./docs/Register-NMMResourceGroup.md)|:white_check_mark:|
DELETE|[Remove-NMMResourceGroup](./docs/Remove-NMMResourceGroup.md)|:white_check_mark:|
POST|[Set-DefaultNMMResourceGroup](./docs/Set-DefaultNMMResourceGroup.md)|:white_check_mark:|
|**Scripted Actions**
GET|[Get-NMMCustomerAzureRunbookSchedule](./docs/Get-NMMCustomerAzureRunbookSchedule.md)|:white_check_mark:|
GET|[Get-NMMCustomerScriptedAction](./docs/Get-NMMCustomerScriptedAction.md)|:white_check_mark:|
GET|[Get-NMMScriptedAction](./docs/Get-NMMScriptedAction.md)|:white_check_mark:|
POST|[Invoke-NMMCustomerScriptedAction](./docs/Invoke-NMMCustomerScriptedAction.md)|:white_check_mark:|
POST|[Invoke-NMMScriptedAction](./docs/Invoke-NMMScriptedAction.md)|:white_check_mark:|
POST|[PH-New-NMMCustomerAzureRunbookSchedule](./docs/PH-New-NMMCustomerAzureRunbookSchedule.md)|:x:|Q3
DELETE|[Remove-NMMCustomerAzureRunbookSchedule](./docs/Remove-NMMCustomerAzureRunbookSchedule.md)|:white_check_mark:|
|**Secure Variables**
GET|[Get-NMMCustomerSecureVariable](./docs/Get-NMMCustomerSecureVariable.md)|:white_check_mark:|
GET|[Get-NMMSecureVariable](./docs/Get-NMMSecureVariable.md)|:white_check_mark:|
POST|[New-NMMCustomerSecureVariable](./docs/New-NMMCustomerSecureVariable.md)|:white_check_mark:|
POST|[New-NMMSecureVariable](./docs/New-NMMSecureVariable.md)|:white_check_mark:|
DELETE|[Remove-NMMCustomerSecureVariable](./docs/Remove-NMMCustomerSecureVariable.md)|:white_check_mark:|
DELETE|[Remove-NMMSecureVariable](./docs/Remove-NMMSecureVariable.md)|:white_check_mark:|
POST|[Set-NMMCustomerSecureVariable](./docs/Set-NMMCustomerSecureVariable.md)|:white_check_mark:|
POST|[Set-NMMSecureVariable](./docs/Set-NMMSecureVariable.md)|:white_check_mark:|
|**Timezones ids**
GET|[Get-NMMTimezones](./docs/Get-NMMTimezones.md)|:x:|Q2
|**Usage**
GET|[Get-NMMUsage](./docs/Get-NMMUsage.md)|:white_check_mark:|
|**User Sessions**
GET|[Get-NMMHostPoolSessions](./docs/Get-NMMHostPoolSessions.md)|:white_check_mark:|
GET|[Get-NMMWorkspaceSessions](./docs/Get-NMMWorkspaceSessions.md)|:white_check_mark:|
POST|[Invoke-NMMUserSessionLogoff](./docs/Invoke-NMMUserSessionLogoff.md)|:x:|Q2
POST|[Invoke-NMMUserSessionDisconnect](./docs/Invoke-NMMUserSessionDisconnect.md)|:x:|Q2
POST|[Invoke-NMMUserSessionMessage](./docs/Invoke-NMMUserSessionMessage.md)|:x:|Q2
|**Workspace**
GET|[Get-NMMWorkspace](./docs/Get-NMMWorkspace.md)|:white_check_mark:|
POST|[New-NMMWorkspace](./docs/New-NMMWorkspace.md)|:white_check_mark:|

