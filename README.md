# PowerShell Module for NMM (Nerdio Manager for MSP)

![Image](https://img.shields.io/badge/PowerShell%205.1%20&%207.3-Ready-blue.svg?color=5391FE&style=flat&logo=powershell)

## About NMMAPI

The NMMAPI PowerShell module is a collection of cmdlets built to interact with the [Nerdio Manager for MSP](https://getnerdio.com/nerdio-manager-for-msp/) REST API.

## Installation

This module can be installed from the PowerShell Gallery with the following command in PowerShell 5.1+

```powershell
    Install-Module NMMAPI
```

After installation, load the module into your PowerShell session:

```powershell
    Import-Module NMMAPI
```

## Keeping NMMAPI up to date

You can update your module to the latest available release on PowerShell Gallery by running the following command;

```powershell
    Update-NMMAPI
```

Alternatively, you can download the module via this Github repository and drop the module folder into your PowerShell modules directory.

## Enabling the REST API in NMM

* First, ensure that your NMM installation configuration has the `REST API` enabled;
* Browse to your NMM installation, navigate to `Settings` and then to `Integrations` - the `REST API` section will have a `Current Status: Disabled` field.
![Image](./screenshots/nav_settings_integrations.png) ![Image](./screenshots/rest_api_enable.png)
* Click on `Disabled`, and the `Enable REST API` dialog will open. The first step will be to create the `API client` - click on the `Run` button, it will take a few seconds to generate the client.
![Image](./screenshots/rest_api_dialog_1.png)
* Next, grant `Admin Consent` by clicking on the `Grant` button - a new window will pop up with the `NMM App Registration` in the Azure portal. You will need to click the `Grant consent for <tenant>` button, and then click `Yes` in the dialog to confirm consent.
![Image](./screenshots/rest_api_dialog_3.png)
* Once complete, navigate back to the `NMM` tab and hit the refresh icon next to the `Grant` button.
![Image](./screenshots/rest_api_dialog_2.png)
* Now we generate the `Client Secret`, by clicking the `Generate` button.
![Image](./screenshots/rest_api_dialog_4.png)
* You will now be presented with all the critical information needed to connect to the `NMM REST API`.
![Image](./screenshots/rest_api_dialog_5.png)

>**Warning**: Be sure to secure your `Client Secret`, it will not be displayed again. However it can be regenerated at any time.

## Setting up the module

* After a successful import of the module, run the following command:

```powershell
    Add-NMMCredentials
```

* You will be prompted to enter your `NMM URL`, `OAuth 2.0 token`, `M365 Tenant ID`, `NMM Client ID`, `NMM Application Scope` and your `NMM Application Secret` that were created during the enablement of the `REST API` - if you need to retrieve the settings again, they are available on the `Settings -> Integration` page of your NMM installation.
* After adding your NMM credentials, the cmdlet will attempt to get a response from the `/rest-api/v1/test` endpoint, and respond with a success or failure.

## How to use the NMMAPI module

This module follows standard PowerShell naming conventions, and in general each action is named appropriately for the task it is intended to perform, for example

* Once `Add-NMMCredentials` has been executed, the module is ready to be used
* Run `Get-NMMCustomers` to get a list of accounts that are configured in your NMM installation
  * From here, you can see your organizations, organized by `ID` and by `Name`.
  * `ID` is key, as that will be used to identify which customer account(s) are being targeted by almost all cmdlets that are included in this module.

**REST API Action**|**PowerShell Verb**
:-----:|:-----:
GET|Get-
DELETE|Remove-
PATCH|Set-
POST|New-

For example,  the `Secure Variables` MSP level endpoint can have the following actions performed;
```powershell
    Get-NMMSecureVariable
    Remove-NMMSecureVariable
    Set-NMMSecureVariable
    New-NMMSecureVariable
```

***

