# NMMAPI - A PowerShell Module for NMM (Nerdio Manager for MSP)

![Image](https://img.shields.io/badge/PowerShell%205.1%20&%207.3-Ready-blue.svg?color=5391FE&style=flat&logo=powershell)

## About NMMAPI

The NMMAPI PowerShell module is a collection of cmdlets built to interact with the [Nerdio Manager for MSP](https://getnerdio.com/nerdio-manager-for-msp/) REST API.

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

* First, ensure that your NMM installation configuration has the `REST API` enabled.
* Browse to your NMM installation, navigate to `Settings` and then to `Integrations` - the `REST API` section will have a `Current Status: Disabled` field.<!-- ![Image](./screenshots/nav_settings_integrations.png) ![Image](./screenshots/rest_api_enable.png) -->
* Click on `Disabled`, and the `Enable REST API` dialog will open. The first step will be to create the `API client` - click on the `Run` button, it will take a few seconds to generate the client.<!-- ![Image](./screenshots/rest_api_dialog_1.png) -->
* Next, grant `Admin Consent` by clicking on the `Grant` button - a new window will pop up with the `NMM App Registration` in the Azure portal. You will need to click the `Grant consent for <tenant>` button, and then click `Yes` in the dialog to confirm consent.<!-- ![Image](./screenshots/rest_api_dialog_3.png) -->
* Once complete, navigate back to the `NMM` tab and hit the refresh icon next to the `Grant` button.<!-- ![Image](./screenshots/rest_api_dialog_2.png) -->
* Now we generate the `Client Secret`, by clicking the `Generate` button.<!-- ![Image](./screenshots/rest_api_dialog_4.png) -->
* You will now be presented with all the critical information needed to connect to the `NMM REST API`.<!-- ![Image](./screenshots/rest_api_dialog_5.png) -->

    >Be sure to secure your `Client Secret`, it will not be displayed again. However it can be regenerated at any time.

***

## Setting up the module

* After a successful import of the module, run the following command:

```powershell
Add-NMMCredentials
```

* You will be prompted to enter your `NMM URL`, `OAuth 2.0 token`, `M365 Tenant ID`, `NMM Client ID`, `NMM Application Scope` and your `NMM Application Secret` that were created during the enablement of the `REST API` - if you need to retrieve the settings again, they are available on the `Settings -> Integration` page of your NMM installation.
* After adding your NMM credentials, the cmdlet will attempt to get a response from the `/rest-api/v1/test` endpoint, and respond with a success or failure.
* For frequent use and portability, there is the `Export-NMMCredentials` and `Import-NMMCredentials` cmdlets that will save your settings to `C:\Users\<username>\NMMAPI\nmmConfig.json` for later use.
    >You should treat this file with the importance it deserves, it is your API key!

***

## Using the module

* Once `Add-NMMCredentials` has been executed, and you've received a confirmation that the test API endpoint was able to be reached, we're ready to go!
* Run `Get-NMMCustomers` to get a list of accounts that are configured in your NMM installation;
  * From here, you can see your organizations, organized by `ID` and by `Name`.
  * `ID` is key, as that will be used to identify which customer account(s) are being targeted by almost all cmdlets that are included in this module.
<br>
<br>

><details>
><summary>This module follows standard PowerShell naming conventions, and in general each action is named appropriately for the task it is intended to perform, expand me for more information on the action/verb structure!</summary>
>
>**REST API Action**|**PowerShell Verb**
>:-----:|:-----:
>GET|Get-
>DELETE|Remove-
>PATCH|Set-
>POST|New- / Invoke-
>
>For example, the `Secure Variables` MSP level endpoint can have the following actions performed;
>
>```powershell
>Get-NMMSecureVariable
>Remove-NMMSecureVariable
>Set-NMMSecureVariable
>New-NMMSecureVariable
>```
>
></details>  
<br>

### Example - *Setting a secure variable for a customer*

It can be useful to leverage secure variables when you have a scripted action that installs software, or performs other tasks that require a customer-unique variable. This allows you to maintain generalized scripts, and only manage the customer secure variables.

In this example, we are going to take manually specify a variable to be created in a customer account.

First, lets find what customer we'd like to create a secure variable for

```powershell
Get-NMMCustomers | Where-Object name -match "demo"

id name
-- ----
54 Demo Customer
```

We can see that our demo customer has the ID of "54" - so we will reference that ID when using the `New-NMMCustomerSecureVariable` cmdlet.

```powershell
New-NMMCustomerSecureVariable -id 54 -variableName NewVariable -variableValue NewValue

job
---
@{id=187416; status=Completed}
```

Now, if you reference the customer log, you will see the REST API user executed the task "Create secure variable."

But wait, theres more! This cmdlet can do a lot more, for example we can pipe the output of our original `Get-NMMCustomers | Where-Object name -match "demo"` command right into `New-NMMCustomerSecureVariable`.

```powershell
Get-NMMCustomers | Where-Object name -match "demo" | New-NMMCustomerSecureVariable -variableName NewVariable1 -variableValue NewValue1

job
---
@{id=187417; status=Completed}
```

We can go even further with this, and there is a search function built into this cmdlet for convenience.

```powershell
New-NMMCustomerSecureVariable -customerSearch demo -variableName NewVariable2 -variableValue NewValue2
Found single customer match - executing on Demo Customer.

job
---
@{id=187418; status=Completed}
```

In the event you enter a broad search term and there are multiple customer matches, you will be provided with a selection menu

```powershell
New-NMMCustomerSecureVariable -customerSearch d -variableName NewVariable3 -variableValue NewValue3           

id name
-- ----
 1 Andy Nolan
 2 Andy Nolan Dev Tenant
 3 Andy Nolan Gamma Tenant
 4 Yet Another Andy Test ENV
42 More Demos
54 Demo Customer


Multiple customers found matching "d", please enter your customer ID: 54

job
---
@{id=187419; status=Completed}
```

## TO DO

Implement more actions for host pools (I left a lot out because they have the potential to be destructive, and I need to test them more.)

*Documentation*

*Desktop Images*
Haven't started on this yet

*Host actions*

* activate/deactivate host
* reimage
* assign users
* delete host
* run scripted action
