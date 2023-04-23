#Region Account Provisioning
function Register-NMMAD {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [int]$nmmId,
        [string]$domainName,
        [string]$domainAdminUser,
        [string]$domainAdminPass,
        [string]$ouPath
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
 
        $requestBody = @(@"
        {
            "nmmId": $($nmmId),
            "domainName": "$($domainName)",
            "domainAdminUsername": "$($domainAdminUser)",
            "domainAdminPassword": "$($domainAdminPass)",
            "ouPath": "$($ouPath)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accountprovisioning/connecttoexistingad" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Register-NMMFileStorage {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [int]$nmmId,
        [string]$uncPath
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
 
        $requestBody = @(@"
        {
            "nmmId": $($nmmId),
            "uncPath": "$($uncPath)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accountprovisioning/configureFileStorage" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Register-NMMNetwork {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [int]$nmmId,
        [string]$resourceGroup,
        [string]$networkId,
        [string]$subnetName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
 
        $requestBody = @(@"
        {
            "nmmId": $($nmmId),
            "existingResourceGroupName": "$($resourceGroup)",
            "existingNetwork": {
              "networkId": "$($networkId)",
              "subnetName": "$($subnetName)"
            }
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accountprovisioning/linknetwork" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Register-NMMTenant {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$subscriptionId,
        [string]$azureAccessToken,
        [string]$graphAccessToken,
        [string]$companyName,
        [System.Boolean]$avdActive
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
 
        $requestBody = @(@"
        {
            "subscriptionId": "$($subscriptionId)",
            "azureAccessToken": "$($azureAccessToken)",
            "graphAccessToken": "$($graphAccessToken)",
            "companyName": "$($companyName)",
            "activeDirectoryType": "ExistingAD",
            "desktopDeploymentOptions": {
              "wvd": true
            }
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accountprovisioning/linktenant" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Accounts
function Get-NMMCustomers {
    [CmdletBinding()]
    Param(
        [Parameter()]
        [String]$search
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts" -Headers $requestHeaders
        if ($search) {
            $result = $result | Where-Object { $_.name -match $search }
        }
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime" 
    }
}
#EndRegion

#Region App Role Assignments
function Get-NMMAppRoleAssignments {
    [CmdletBinding()]
    Param()
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "$nmmApiConstruct/app-role-assignments" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMAppRoles {
    [CmdletBinding()]
    Param()
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "$nmmApiConstruct/app-role-assignments/roles" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Authentication
function Add-NMMCredentials {
    Param(
        [System.Uri]$nmmBaseUri,
        [System.Uri]$nmmoAuthToken,
        [ValidatePattern('^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$')][string]$nmmTenantId,
        [ValidatePattern('^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$')][string]$nmmClientId,
        [ValidatePattern('^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}\/\.default$')][string]$nmmScope,
        [securestring]$nmmSecretx
    )
    BEGIN {
        if (!$nmmBaseUri) {
            [System.Uri]$nmmBaseUri = Read-Host -Prompt 'Please input your full NMM URI, e.g. https://nmm.democompany.com'
            Set-Variable -Name 'nmmBaseUri' -Value $nmmbaseUri -Scope Global
        }
        if (!$nmmoAuthToken) {
            [System.Uri]$nmmoAuthToken = (Read-Host -Prompt 'Please input your OAuth 2.0 token URL').Trim()
             # Define the regular expression pattern for the required URI string
            $nmmoAuthRegex = "https://login.microsoftonline.com/.+/oauth2/v2.0/token$"
            if($nmmoAuthToken.AbsoluteUri -match $nmmoAuthRegex){
                Set-Variable -Name 'nmmOauth' -Value $nmmoAuthToken.AbsoluteUri -Scope Global
            }
            else {
                Write-Error "Invalid OAuth2.0 URL entered."
                Exit
            }
        }
        if (!$nmmtenantId) {
            do {
                $nmmtenantID = (Read-Host -Prompt 'Please input your tenant ID').Trim()
                if ($nmmtenantId -eq 'quit'){
                    Exit
                }
                elseif ($nmmtenantId -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'){
                    Write-Error 'Invalid tenant ID format. Please try again.'
                }
            } until ($nmmtenantId -match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$')
            Set-Variable -Name 'nmmTenantId' -Value $nmmtenantId -Scope Global 
        }
        if (!$nmmClientId) {
            do {
                $nmmClientId = (Read-Host -Prompt 'Please input your client ID').Trim()
                if ($nmmClientId -eq 'quit'){
                    Exit
                }
                elseif ($nmmClientId -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'){
                    Write-Error 'Invalid client ID format. Please try again.'
                }
            } until ($nmmClientId -match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$')
            Set-Variable -Name 'nmmClientId' -Value $nmmclientId -Scope Global 
        }
        if (!$nmmscope) {
            do {
                $nmmscope = (Read-Host -Prompt 'Please input your scope').Trim()
                if ($nmmscope -eq 'quit'){
                    Exit
                }
                elseif ($nmmscope -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}/\.default$'){
                    Write-Error 'Invalid scope format. Please try again.'
                }
            } until ($nmmscope -match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}\/\.default$')
            Set-Variable -Name 'nmmScope' -Value $nmmscope -Scope Global 
        }
        if (!$nmmsecretx) {
            [SecureString]$nmmsecretx = Read-Host -Prompt 'Please input your secret' -AsSecureString
            Set-Variable -Name 'nmmSecret' -Value $nmmSecretx -Scope Global
        }
        #Set-Variable -Name 'nmmSecret' -Value $($nmmconfsecret | ConvertTo-SecureString -AsPlainText -Force) -Scope Global 
    }
    PROCESS {
        Set-Variable -Name 'nmmApiConstruct' -Value "$nmmApiConstruct" -Scope Global
        Write-Host "Testing connectivity to the NMM API located at $nmmBaseUri"
        Test-NMMAPI
    }
}
function Export-NMMCredentials {
    [CmdletBinding()]
    Param()
    BEGIN {
        $nmmConfig = "$($env:USERPROFILE)\NMMAPI\nmmConfig.xml"
        if ($nmmBaseUri -and $nmmoAuth -and $nmmTenantId -and $nmmClientId -and $nmmScope -and $nmmSecret) {
            $ssConvert = $nmmSecret | ConvertFrom-SecureString
            New-Item -ItemType Directory -Force -Path (Split-Path $nmmConfig)
            $begin = Get-Date
            $OK = $true
        }
        else {
            Write-Host "Missing one or more REST API credentials. Please run Add-NMMCredentials and try again."
        }
    }
    PROCESS {
        if ($OK -eq $true) {
            $exportCreds = @{
                "nmmBaseUri"  = $nmmBaseUri
                "nmmOauth"    = $nmmOauth
                "nmmTenantId" = $nmmTenantId
                "nmmClientId" = $nmmClientId
                "nmmScope"    = $nmmScope
                "nmmSecret"   = $ssConvert
            }
            $exportCreds | Export-CliXml -Path $nmmConfig -Force
        }
        else {
            Write-Error "Unable to output API configuration settings to $nmmConfig"
        }    
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMToken {

    if (!$nmmBaseURI -or !$nmmOauth -or !$nmmTenantId -or !$nmmClientId -or !$nmmScope -or !$nmmSecret) {
        Write-Error "One or more configuration variables are missing. Please run Add-NMMCredentials to re-add and try again."
    }
    else{
    $tokenSplat = @{
        grant_type = "client_credentials";
        client_secret = ($nmmSecret | ConvertFrom-SecureString -AsPlainText);
        client_id = $nmmClientId;
        scope = $nmmScope;
        }
        $nmmOAToken = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$nmmTenantId/oauth2/v2.0/token" -Method POST -Body $tokenSplat
        Set-Variable -Name 'nmmTokenExp' -Value (Get-Date).AddMinutes(59) -Scope Global
        Set-Variable -Name 'nmmToken' -Value $nmmOAToken -Scope Global
    }
}
function Import-NMMCredentials {
    [CmdletBinding()]
    Param()
    BEGIN {
        $nmmConfig = "$($env:USERPROFILE)\NMMAPI\nmmConfig.xml"
        if(Test-Path $nmmConfig){
            $nmmCredentials = Import-CliXml -Path $nmmConfig -ErrorAction Stop
            $OK = $True
        } else{
            Write-Warning "Unable to import NMM API config path from $nmmConfig. Run Add-NMMCredentials and input manually."
        }
    }
    PROCESS {
        if ($OK -eq $true){
            Set-Variable -Name 'nmmBaseUri' -Value $nmmCredentials.nmmbaseUri -Scope Global 
            Set-Variable -Name 'nmmOauth' -Value $nmmCredentials.nmmOauth -Scope Global 
            Set-Variable -Name 'nmmTenantId' -Value $nmmCredentials.nmmTenantId -Scope Global 
            Set-Variable -Name 'nmmClientId' -Value $nmmCredentials.nmmClientId -Scope Global 
            Set-Variable -Name 'nmmScope' -Value $nmmCredentials.nmmScope -Scope Global 
            Set-Variable -Name 'nmmSecret' -Value $($nmmCredentials.nmmSecret | ConvertTo-SecureString) -Scope Global
            Set-Variable -Name 'nmmApiConstruct' -Value "https://$($nmmCredentials.nmmbaseuri)/rest-api/v1" -Scope Global
            Test-NMMAPI

        } else {
            Write-Error "Unable to import NMM API config path from $nmmConfig. Run Add-NMMCredentials and input manually."
        }    
    }
}
function Test-NMMAPI {
    [CmdletBinding()]
    Param()
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "$nmmApiConstruct/test" -Headers $requestHeaders
        if($result -match "Hi, rest api"){
            $OK = $true
        }
        else{
            $OK = $false
        }
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK -eq $true) {
            Write-Output "Successfully connected to the NMM API located at $nmmBaseUri!"
        }
        else{
            Write-Output "Unable to connect to the NMM API."
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Backup
function Disable-NMMCustomerBackup {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [string]$sourceResourceId,
    [string]$protectedItemId,
    [int]$nmmId,
    [boolean]$removeAllBackups
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $requestBody = @(@"
        {
            "sourceResourceId": "$($sourceResourceId)",
            "protectedItemId": "$($protectedItemId)",
            "removeAllBackups": $removeAllBackups
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
            $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/backup/disable" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
            $OK = $True

        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Enable-NMMCustomerBackup {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)]
    [string]$sourceResourceId,
    [string]$backupPolicy,
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $requestBody = @(@"
        {
            "sourceResourceId": "$($sourceResourceId)",
            "policyId": "$($backupPolicy)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
            $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/backup/enable" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
            $OK = $True

        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMCustomerProtectedItems {
    # Gets customer protected items
    [CmdletBinding()]
    Param(        
    [Parameter(Mandatory)] 
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
            $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/backup/protectedItems" -Headers $requestHeaders
            $result | Add-Member -MemberType NoteProperty "nmmId" -Value $nmmId
            $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMCustomerRecoveryPoints {
    # Gets customer protected items
    [CmdletBinding()]
    Param(        
    [Parameter(Mandatory,ValueFromPipeLine,ValueFromPipelineByPropertyName)] 
    [int]$nmmId,
    [Alias("id")]
    [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [string]$protectedItemId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
            $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/backup/recoveryPoints?protectedItemId=$($protectedItemId)" -Headers $requestHeaders
            $result | Add-Member -MemberType NoteProperty "nmmId" -Value $nmmId
            $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Invoke-NMMCustomerBackup {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [string]$sourceResourceId,
    [string]$protectedItemId,
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $requestBody = @(@"
        {
            "sourceResourceId": "$($sourceResourceId)",
            "protectedItemId": "$($protectedItemId)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
            $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/backup" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
            $OK = $True

        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Invoke-NMMCustomerRestore {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [string]$sourceResourceId,
    [string]$recoveryPointId,
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $requestBody = @(@"
        {
            "sourceResourceId": "$($sourceResourceId)",
            "recoveryPointId": "$($recoveryPointId)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
            $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/backup/restore" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
            $OK = $True

        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Cost Estimator
function Get-NMMEstimate {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $false)] 
    [int]$estimateID
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
            if($estimateId){
            $result = Invoke-RestMethod -Uri "$nmmApiConstruct/costestimator/$($estimateID)" -Headers $requestHeaders
            $OK = $True
            }
            else{
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/costestimator/list" -Headers $requestHeaders
                $OK = $True
            }
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Desktop Image
function Get-NMMDesktopImage{
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $customerDesktops = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/desktop-image" -Headers $requestHeaders
        $customerDesktops | Add-Member -MemberType NoteProperty "nmmId" -Value $($nmmId)
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $customerDesktops
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMDesktopImageChangelog{
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$name,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias("subscriptionId")]
        [string]$subscription
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $desktopChangelog = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/desktop-image/$($subscription)/$($resourceGroup)/$($name)/change-log" -Headers $requestHeaders
       # $desktopChangelog | Add-Member -MemberType NoteProperty "nmmId" -Value $($nmmId)
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $desktopChangelog
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMDesktopImageDetail{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$name,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias("subscriptionId")]
        [string]$subscription
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $desktopDetail = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/desktop-image/$($subscription)/$($resourceGroup)/$($name)" -Headers $requestHeaders
       # $desktopDetail | Add-Member -MemberType NoteProperty "nmmId" -Value $($nmmId)
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $desktopDetail
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Start-NMMDesktopImage{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$name,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias("subscriptionId")]
        [string]$subscription
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $desktopStart = Invoke-RestMethod -Method PUT -Uri "$nmmApiConstruct/accounts/$($nmmId)/desktop-image/$($subscription)/$($resourceGroup)/$($name)/start" -Headers $requestHeaders
       # $desktopStart | Add-Member -MemberType NoteProperty "nmmId" -Value $($nmmId)
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $desktopStart
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Stop-NMMDesktopImage{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$name,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [Alias("subscriptionId")]
        [string]$subscription
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $desktopStop = Invoke-RestMethod -Method PUT -Uri "$nmmApiConstruct/accounts/$($nmmId)/desktop-image/$($subscription)/$($resourceGroup)/$($name)/stop" -Headers $requestHeaders
       # $desktopStop | Add-Member -MemberType NoteProperty "nmmId" -Value $($nmmId)
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $desktopStop
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Directories
function Get-NMMDirectories {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $false)] 
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
            if($nmmId){
            $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/directories" -Headers $requestHeaders
            $OK = $True
            }
            else{
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/directories" -Headers $requestHeaders
                $OK = $True
            }
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region FSLogix Configs
function Get-NMMFSlogixConfig {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
            $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/fslogix" -Headers $requestHeaders
            $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Host
function Get-NMMHosts{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("hostPoolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPool
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $hosts = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPool)/hosts" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $hosts
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Restart-NMMHost{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("hostPoolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPool,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $hosts = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPool)/hosts/$($hostName)/restart" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $hosts
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Start-NMMHost{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("hostPoolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPool,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostName,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false)]
        [String]$customerSearch
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $hosts = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPool)/hosts/$($hostName)/start" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $hosts
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Stop-NMMHost{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("hostPoolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPool,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $hosts = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPool)/hosts/$($hostName)/stop" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $hosts
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Host Pools
function Get-NMMHostPool{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $customerHostPools = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool" -Headers $requestHeaders
        $customerHostPools | Add-Member -MemberType NoteProperty "nmmId" -Value $($nmmId)
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $customerHostPools
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMHostPoolAD{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("poolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPoolName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $allCustomerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPoolName)/active-directory" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $allCustomerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMHostPoolAssignedUsers{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("poolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPoolName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $allCustomerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPoolName)/assigned-users" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $allCustomerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMHostPoolAutoscale{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("poolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPoolName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $allCustomerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPoolName)/autoscale-configuration" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $allCustomerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMHostPoolAVD{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("poolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPoolName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $allCustomerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPoolName)/avd" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $allCustomerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMHostPoolFSLogix{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("poolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPoolName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $allCustomerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPoolName)/fslogix" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $allCustomerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMHostPoolRDPSettings{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("poolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPoolName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $allCustomerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPoolName)/rdp-settings" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $allCustomerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMHostPoolSessionTimeouts{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("poolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPoolName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $allCustomerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPoolName)/session-timeouts" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $allCustomerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMHostPoolTags{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("poolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPoolName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $allCustomerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPoolName)/tags" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $allCustomerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMHostPoolVMDeployment{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("poolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPoolName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $allCustomerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPoolName)/vm-deployment" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $allCustomerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Invoices
function Get-NMMInvoiceID {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [int]$invoiceId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/invoices/$($invoiceId)" -Headers $requestHeaders
                $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMInvoices {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [datetime]$startTime,
    [Parameter(Mandatory)] 
    [datetime]$endTime
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $startTimeStr = [uri]::EscapeDataString($startTime.ToString("MM/dd/yyyy"))
        $endTimeStr = [uri]::EscapeDataString($endTime.ToString("MM/dd/yyyy"))

        $begin = Get-Date
    }
    PROCESS {
        Try{
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/invoices?periodStart=$($startTimeStr)&periodEnd=$($endTimeStr)&hidePaid=false&hideUnpaid=false" -Headers $requestHeaders
                $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMInvoicesPaid {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [datetime]$startTime,
    [Parameter(Mandatory)] 
    [datetime]$endTime
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $startTimeStr = [uri]::EscapeDataString($startTime.ToString("MM/dd/yyyy"))
        $endTimeStr = [uri]::EscapeDataString($endTime.ToString("MM/dd/yyyy"))

        $begin = Get-Date
    }
    PROCESS {
        Try{
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/invoices?periodStart=$($startTimeStr)&periodEnd=$($endTimeStr)&hidePaid=false&hideUnpaid=true" -Headers $requestHeaders
                $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMInvoicesUnpaid {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [datetime]$startTime,
    [Parameter(Mandatory)] 
    [datetime]$endTime
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $startTimeStr = [uri]::EscapeDataString($startTime.ToString("MM/dd/yyyy"))
        $endTimeStr = [uri]::EscapeDataString($endTime.ToString("MM/dd/yyyy"))

        $begin = Get-Date
    }
    PROCESS {
        Try{
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/invoices?periodStart=$($startTimeStr)&periodEnd=$($endTimeStr)&hidePaid=true&hideUnpaid=false" -Headers $requestHeaders
                $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Jobs
function Get-NMMJob {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [int]$jobId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/job/$($jobId)" -Headers $requestHeaders
                $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMJobTasks {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [int]$jobId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/job/$($jobId)/tasks" -Headers $requestHeaders
                $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Restart-NMMJob {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [int]$jobId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
                $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/job/$($jobId)" -Headers $requestHeaders
                $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Networks
function Get-NMMAllNetworks {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $false)] 
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
            $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/networks/all" -Headers $requestHeaders
            $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMManagedNetworks {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $false)] 
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
            $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/networks" -Headers $requestHeaders
            $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Register-NMMNetwork {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [int]$nmmId,
    [string]$networkId,
    [string]$subnetName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $requestBody = @(@"
        {
            "networkId": "$($networkId)",
            "subnetName": "$($subnetName)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
            $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/networks/link" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
            $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Recovery Vault
function Get-NMMAllRecoveryVaults{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $allCustomerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/recovery-vault/allvaults" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $allCustomerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMLinkedRecoveryVaults{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $customerVaults = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/recovery-vault" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $customerVaults
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMRecoveryVaultPolicies{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [String]$vaultId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $customerVaultPolicy = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/recovery-vault/policies?vaultId=$($vaultId)" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $customerVaultPolicy
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMRecoveryVaultPoliciesByRegion{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [String]$region
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $customerRvPolRegion = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/recovery-vault/regionpolicyinfo/$($region)" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $customerRvPolRegion
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMRecoveryVaultPolicy{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [String]$policyName,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [String]$vaultId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $customerVaultPolicy = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/recovery-vault/policy?vaultId=$($vaultId)&policyName=$($policyName)" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $customerVaultPolicy
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function New-NMMRecoveryVault{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [string]$vaultName,
        [string]$resourceGroup,
        [string]$location,
        [string]$replicationType
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
        $rgValidation = Get-NMMResourceGroup -nmmId $nmmId | Where-Object name -match $resourceGroup
        
        if($rgValidation.Count -eq 1){
            Write-Host "Found a match for resource group, using $($rgValidation.resourceGroupId) to create a new Recovery Vault!"
            $matchedResourceGroup = $rgValidation.resourceGroupId
        }
        if($rgValidation.Count -gt 1){
            $rgValidation | Format-Table
            [string]$customerSelection = Read-Host "Multiple resource groups found matching ""$resourceGroup"", please copy and paste the entire resource group ID." 
            $matchedResourceGroup = $customerSelection
        }
        if($rgValidation.Count -eq 0){
            Write-Error "No matches found for specified resource group: $($resourceGroup)"
            Exit
        }

        $requestBody = @(@"
        {
            "vaultName": "$($vaultName)",
            "resourceGroupId": "$($matchedResourceGroup)",
            "location": "$($location)",
            "replicationType": "$($replicationType)"
        }
"@)

    }
    PROCESS {
        Try{
        $newVault = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/recovery-vault" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $newVault
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Register-NMMRecoveryVault{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$vaultID
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
        $vaultValidation = Get-NMMAllRecoveryVaults -nmmId $nmmId | Where-Object id -match $vaultID
        
        if($vaultValidation.Count -eq 1){
            Write-Host "Found a match for vault ID, linking $($vaultValidation.id) to NMM!"
            $matchedVaultId = $vaultValidation.id
        }
        if($vaultValidation.Count -gt 1){
            $vaultValidation | Format-Table
            [string]$customerSelection = Read-Host "Multiple vaults matching ""$vaultID"", please copy and paste the entire vault ID." 
            $matchedVaultID = $customerSelection
        }
        if($vaultValidation.Count -eq 0){
            Write-Error "No matches found for specified vault: $($vaultID)"
            Exit
        }
    }
    PROCESS {
        Try{
        $newVault = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/recovery-vault/link/vault?vaultId=$($matchedVaultId)" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $newVault
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Remove-NMMRecoveryVaultPolicy{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [String]$policyName,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [String]$vaultId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $customerVaultPolicy = Invoke-RestMethod -Method DELETE -Uri "$nmmApiConstruct/accounts/$($nmmId)/recovery-vault/policy?vaultId=$($vaultId)&policyName=$($policyName)" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $customerVaultPolicy
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Unregister-NMMRecoveryVault{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$vaultID
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
        $vaultValidation = Get-NMMAllRecoveryVaults -nmmId $nmmId | Where-Object id -match $vaultID
        
        if($vaultValidation.Count -eq 1){
            Write-Host "Found a match for vault ID, unlinking $($vaultValidation.id) to NMM!"
            $matchedVaultId = $vaultValidation.id
        }
        if($vaultValidation.Count -gt 1){
            $vaultValidation | Format-Table
            [string]$customerSelection = Read-Host "Multiple vaults matching ""$vaultID"", please copy and paste the entire vault ID you wish to unlink." 
            $matchedVaultID = $customerSelection
        }
        if($vaultValidation.Count -eq 0){
            Write-Error "No matches found for specified vault: $($vaultID)"
            Exit
        }
    }
    PROCESS {
        Try{
        $newVault = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/recovery-vault/unlink/vault?vaultId=$($matchedVaultId)" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $newVault
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Reservations
function Get-NMMReservationId{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$reservationId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $custReservationSpecific = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/reservations/$($reservationId)" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $custReservationSpecific
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMReservationIdResources{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$reservationId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $custReservationSpecific = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/reservations/$($reservationId)/resources" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $custReservationSpecific
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMReservations{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $custReservations = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/reservations" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $custReservations
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function New-NMMReservation{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [string]$orderId,
        [string]$orderName,
        [int]$price,
        [string]$billingPlan,
        [string]$startDate,
        [string]$term,
        [string]$region,
        [string]$vmSize,
        [bool]$instanceFlex,
        [int]$quantity
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date

        # I have no idea what I am doing
        if($instanceFlex -eq $true){
            $flex = "true"
        }else{
            $flex = "false"
        }

        $requestBody = @(@"
        {
            "orderId": "$($orderId)",
            "orderName": "$($orderName)",
            "price": $($price),
            "billingPlan": "$($billingPlan)",
            "startDate": "$($startDate)T00:00:00.000Z",
            "term": "$($term)",
            "region": "$($region)",
            "vmSize": "$($vmSize)",
            "instanceFlexibility": $($flex),
            "quantity": $($quantity)
          }
"@)

    }
    PROCESS {
        Try{
        $newVault = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/reservations" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $newVault
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Remove-NMMReservation{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$reservationId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $custReservationSpecific = Invoke-RestMethod -Method DELETE -Uri "$nmmApiConstruct/accounts/$($nmmId)/reservations/$($reservationId)" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $custReservationSpecific
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function New-NMMReservation{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int32]$reservationId,
        [string]$orderId,
        [string]$orderName,
        [int]$price,
        [string]$billingPlan,
        [string]$startDate,
        [string]$term,
        [string]$region,
        [string]$vmSize,
        [bool]$instanceFlex,
        [int]$quantity
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date

        # I have no idea what I am doing
        if($instanceFlex -eq $true){
            $flex = "true"
        }else{
            $flex = "false"
        }

        $requestBody = @(@"
        {
            "orderId": "$($orderId)",
            "orderName": "$($orderName)",
            "price": $($price),
            "billingPlan": "$($billingPlan)",
            "startDate": "$($startDate)T00:00:00.000Z",
            "term": "$($term)",
            "region": "$($region)",
            "vmSize": "$($vmSize)",
            "instanceFlexibility": $($flex),
            "quantity": $($quantity)
          }
"@)

    }
    PROCESS {
        Try{
        $newVault = Invoke-RestMethod -Method PUT -Uri "$nmmApiConstruct/accounts/$($nmmId)/reservations/$($reservationId)" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $newVault
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Resource Group
function Get-NMMResourceGroup {
    # Pulls RGs linked to the MSP's NMM instance, unless using the -nmmId flag.
    [CmdletBinding()]
    Param(        
    [Parameter(Mandatory = $false)] 
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        
            if($nmmId){
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/resource-group" -Headers $requestHeaders
                $OK = $True
            }
            else {
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/resource-group" -Headers $requestHeaders
                $OK = $True
            }

        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Register-NMMResourceGroup {
    # Registers an RG from the MSP's NMM instance, unless using the -nmmId flag.
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [string]$subscriptionId,
    [string]$resourceGroup,
    [Parameter(Mandatory = $false)] 
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $requestBody = @(@"
        {
            "resourceGroup": "$($resourceGroup)",
            "subscriptionId": "$($subscriptionId)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        
            if($nmmId){
                $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/resource-group/linked" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
                $OK = $True
            }
            else {
                $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/resource-group/linked" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
                $OK = $True
            }

        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Remove-NMMResourceGroup {
    # Removed specified RG from the MSP's NMM instance, unless using the -nmmId flag.
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [string]$subscriptionId,
    [string]$resourceGroup,
    [Parameter(Mandatory = $false)] 
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $requestBody = @(@"
        {
            "resourceGroup": "$($resourceGroup)",
            "subscriptionId": "$($subscriptionId)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        
            if($nmmId){
                $result = Invoke-RestMethod -Method DELETE -Uri "$nmmApiConstruct/accounts/$($nmmId)/resource-group/linked" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
                $OK = $True
            }
            else {
                $result = Invoke-RestMethod -Method DELETE -Uri "$nmmApiConstruct/resource-group/linked" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
                $OK = $True
            }

        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Set-DefaultNMMResourceGroup {
    # Set specified RG from the MSP's NMM instance as default, unless using the -nmmId flag.
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [string]$subscriptionId,
    [string]$resourceGroup,
    [Parameter(Mandatory = $false)] 
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $requestBody = @(@"
        {
            "resourceGroup": "$($resourceGroup)",
            "subscriptionId": "$($subscriptionId)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        
            if($nmmId){
                $result = Invoke-RestMethod -Method PUT -Uri "$nmmApiConstruct/accounts/$($nmmId)/resource-group/setDefault" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
                $OK = $True
            }
            else {
                $result = Invoke-RestMethod -Method PUT -Uri "$nmmApiConstruct/resource-group/setDefault" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
                $OK = $True
            }

        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Scripted Actions
function Get-NMMCustomerAzureRunbookSchedule {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$scriptID
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/scripted-actions/$($scriptId)/schedule" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMCustomerScriptedAction {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/scripted-actions" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMScriptedAction {
    [CmdletBinding()]
    Param()
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "$nmmApiConstruct/scripted-actions" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Invoke-NMMCustomerScriptedAction {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [int]$scriptId,
    [int]$timeoutMins
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
        if($timeoutMins = $null){
            $timeoutMins = 30
        }
        $defaultResourceGroup = (Get-NMMResourceGroup -nmmId $($nmmId) | Where-Object isDefault -eq True).name
        $requestBody = @(@"
        {
            "adConfigId": null,
            "paramsBindings": {
              "ResourceGroup": {
                "value": "$($defaultResourceGroup)",
                "isSecure": false
              }
            },
            "minutesToWait": 30
          }
"@)
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/scripted-actions/$($scriptId)/execution" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Invoke-NMMScriptedAction {
    [CmdletBinding()]
    Param (
[Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
    [int]$scriptId,
    [int]$timeoutMins
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
        if($timeoutMins = $null){
            $timeoutMins = 30
        }
        $defaultResourceGroup = (Get-NMMResourceGroup | Where-Object isDefault -eq True).name
        $requestBody = @(@"
        {
            "adConfigId": null,
            "paramsBindings": {
              "ResourceGroup": {
                "value": "$($defaultResourceGroup)",
                "isSecure": false
              }
            },
            "minutesToWait": 30
          }
"@)
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/scripted-actions/$($scriptId)/execution" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
# Placeholder for now.
<# function Remove-NMMCustomerAzureRunbookSchedule {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$scriptID
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method DELETE -Uri "$nmmApiConstruct/accounts/$($nmmId)/scripted-actions/$($scriptId)/schedule" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
 #>
function Remove-NMMCustomerAzureRunbookSchedule {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$scriptID
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method DELETE -Uri "$nmmApiConstruct/accounts/$($nmmId)/scripted-actions/$($scriptId)/schedule" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Secure Variables
function Get-NMMCustomerSecureVariable {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $customerVars = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/secure-variables" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            # Write-Output "Secure Vars for $($nmmId)"
            Write-Output $customerVars
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMSecureVariable {
    [CmdletBinding()]
    Param()
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "$nmmApiConstruct/secure-variables" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function New-NMMCustomerSecureVariable {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory)]
        [string]$variableName,
        [string]$variableValue,
        [Parameter(Mandatory = $false)] 
        [string]$scriptedAction
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
        $requestBody = @(@"
        {
            "name": "$($variableName)",
            "scriptedActions": [$scriptedAction],
            "value": "$($variableValue)"
        }
"@)
    }
    PROCESS {
        Try{
        $customerVars = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            # Write-Output "Secure Vars for $($nmmId)"
            Write-Output $customerVars
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function New-NMMSecureVariable {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$variableName,
        [string]$variableValue,
        [Parameter(Mandatory = $false)] 
        [string]$scriptedAction
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
 
        $requestBody = @(@"
        {
            "name": "$($variableName)",
            "scriptedActions": [$scriptedAction],
            "value": "$($variableValue)"
        }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Remove-NMMCustomerSecureVariable {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory)]
        [string]$variableName,
        [string]$variableValue,
        [Parameter(Mandatory = $false)] 
        [string]$scriptedAction
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date

        $requestBody = @(@"
        {
            "name": "$($variableName)"
        }
"@)
    }
    PROCESS {
        Try{
        $customerVars = Invoke-RestMethod -Method DELETE -Uri "$nmmApiConstruct/accounts/$($nmmId)/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            # Write-Output "Secure Vars for $($nmmId)"
            Write-Output $customerVars
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Remove-NMMSecureVariable {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$variableName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
 
        $requestBody = @(@"
        {
            "name": "$($variableName)"
        }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method DELETE -Uri "$nmmApiConstruct/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Set-NMMCustomerSecureVariable {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Parameter(Mandatory)]
        [string]$variableName,
        [string]$variableValue,
        [Parameter(Mandatory = $false)] 
        [string]$scriptedAction
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date

        $requestBody = @(@"
        {
            "name": "$($variableName)",
            "scriptedActions": [$scriptedAction],
            "value": "$($variableValue)"
        }
"@)
    }
    PROCESS {
        Try{
        $customerVars = Invoke-RestMethod -Method PUT -Uri "$nmmApiConstruct/accounts/$($nmmId)/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            # Write-Output "Secure Vars for $($nmmId)"
            Write-Output $customerVars
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Set-NMMSecureVariable {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$variableName,
        [string]$variableValue,
        [Parameter(Mandatory = $false)] 
        [string]$scriptedAction
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
 
        $requestBody = @(@"
        {
            "name": "$($variableName)",
            "scriptedActions": [$scriptedAction],
            "value": "$($variableValue)"
        }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method PUT -Uri "$nmmApiConstruct/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Usage
function Get-NMMUsage {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [datetime]$startTime,
    [Parameter(Mandatory)] 
    [datetime]$endTime,
    [Parameter(Mandatory)] 
    [bool]$withDetails,
    [Parameter(Mandatory = $false)]
    [int]$nmmId 
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $startTimeStr = [uri]::EscapeDataString($startTime.ToString("MM/dd/yyyy"))
        $endTimeStr = [uri]::EscapeDataString($endTime.ToString("MM/dd/yyyy"))

        $begin = Get-Date
    }
    PROCESS {
        Try{
                if($nmmId){
                    $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/usages?startDate=$($startTimeStr)&endDate=$($endTimeStr)&withDetails=$($withDetails)" -Headers $requestHeaders
                    $OK = $True
                }
                else{
                $result = Invoke-RestMethod -Uri "$nmmApiConstruct/usages?startDate=$($startTimeStr)&endDate=$($endTimeStr)&withDetails=$($withDetails)" -Headers $requestHeaders
                $OK = $True
                }
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region User Sessions
function Get-NMMHostPoolSessions{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("hostPoolName")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$hostPool
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $hostPoolSessions = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/host-pool/$($subscription)/$($resourceGroup)/$($hostPool)/sessions" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $hostPoolSessions
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function Get-NMMWorkspaceSessions{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [int]$nmmId,
        [Alias("subscriptionId")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$subscription,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$resourceGroup,
        [Alias("workspace")]
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string]$workspaceName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $workspaceSessions = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/workspace/$($subscription)/$($resourceGroup)/$($workspaceName)/sessions" -Headers $requestHeaders
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $workspaceSessions
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion

#Region Workspace
function Get-NMMWorkspace {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [int]$nmmId
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "$nmmApiConstruct/accounts/$($nmmId)/workspace" -Headers $requestHeaders
        $result | Add-Member -MemberType NoteProperty "nmmId" -Value $($nmmId)

        $betterOut = [PSCustomObject]@{
            nmmFriendlyName     = $($result.friendlyName)
            nmmDescription      = $($result.description)
            nmmId          = $($result.nmmId)
            subscriptionId      = $($result.id.subscriptionId)
            resourceGroup       = $($result.id.resourceGroup)
            workspaceName       = $($result.id.name)
        }
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $betterOut
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
function New-NMMWorkspace {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory)] 
    [int]$nmmId,
    [Parameter(Mandatory)] 
    [string]$region,
    [Parameter(Mandatory)] 
    [string]$resourceGroup,
    [Parameter(Mandatory)] 
    [string]$workspaceName
    )
    BEGIN{
        if(!$nmmToken -or ((New-TimeSpan -Start $nmmTokenExp -End (Get-Date)).Minutes -gt -1)){
            Write-Warning "No NMM Token present, or expired, running Get-NMMToken now."
            Get-NMMToken
        }
        $requestHeaders = @{
            'accept' = 'application/json';
            'authorization' = "Bearer " + $nmmToken.access_token
        }
        $requestBody = @(@"
        {
            "region": "$($region)",
            "resourceGroup": "$($resourceGroup)",
            "workspaceName": "$($workspaceName)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method POST -Uri "$nmmApiConstruct/accounts/$($nmmId)/workspace" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
        $OK = $True
        }
        Catch{
            $OK = $false
            if($_.ErrorDetails.Message){
                Write-Error $_.ErrorDetails.Message
            }
            else {
                Write-Error $_
            }
        }
        If ($OK) {
            Write-Output $result
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
#EndRegion