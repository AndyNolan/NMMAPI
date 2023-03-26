#Region Authentication & Credentials
function Add-NMMCredentials {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [String]
        $baseUri,
        $oAuthToken,
        $tenantId,
        $clientId,
        $scope,
        $secret
    )
    process {
        if (!$baseUri) {
            $baseUri = Read-Host -Prompt 'Please input your NMM URL, e.g. nmm.democompany.com'
        }
        if (!$oAuthToken) {
            $oAuthToken = Read-Host -Prompt 'Please input your OAuth 2.0 token'
        }
        if (!$tenantId) {
            $tenantId = Read-Host -Prompt 'Please input your tenant ID'
        }
        if (!$clientId) {
            $clientId = Read-Host -Prompt 'Please input your client ID'
        }
        if (!$scope) {
            $scope = Read-Host -Prompt 'Please input your scope'
        }
        if (!$secret) {
            $secret = Read-Host -Prompt 'Please input your secret'
        }
        Set-Variable -Name 'nmmBaseUri' -Value $baseUri -Scope Global 
        Set-Variable -Name 'nmmOauth' -Value $oAuthToken -Scope Global 
        Set-Variable -Name 'nmmTenantId' -Value $tenantId -Scope Global 
        Set-Variable -Name 'nmmClientId' -Value $clientId -Scope Global 
        Set-Variable -Name 'nmmScope' -Value $scope -Scope Global 
        Set-Variable -Name 'nmmSecret' -Value $secret -Scope Global 
    }
}
function Get-NMMToken {

    if (!$nmmBaseURI -or !$nmmOauth -or !$nmmTenantId -or !$nmmClientId -or !$nmmScope -or !$nmmSecret) {
        Write-Error "One or more configuration variables are missing. Please run Add-NMMCredentials to re-add and try again."
    }
    else{
    $tokenSplat = @{
        grant_type = "client_credentials";
        client_secret = $nmmSecret;
        client_id = $nmmClientId;
        scope = $nmmScope;
        }
        $nmmOAToken = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$($nmmTenantId)/oauth2/v2.0/token" -Method POST -Body $tokenSplat
        Set-Variable -Name 'nmmTokenExp' -Value (Get-Date).AddMinutes(59) -Scope Global
        Set-Variable -Name 'nmmToken' -Value $nmmOAToken -Scope Global
    }
}
#EndRegion Authentication & Credentials

#Region Accounts
function Get-NMMCustomers {
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
        $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts" -Headers $requestHeaders
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
        
    }
}
#EndRegion Accounts

#Region Account Provisioning
function Register-NMMTenant {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
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
        $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accountprovisioning/linktenant" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Register-NMMNetwork {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [int]$accountId,
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
            "accountId": $($accountId),
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
        $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accountprovisioning/linknetwork" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Register-NMMAD {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [int]$accountId,
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
            "accountId": $($accountId),
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
        $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accountprovisioning/connecttoexistingad" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Register-NMMFileStorage {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [int]$accountId,
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
            "accountId": $($accountId),
            "uncPath": "$($uncPath)"
          }
"@)
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accountprovisioning/configureFileStorage" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
#EndRegion Accounting Provisioning

#Region Backup
function Get-NMMCustomerProtectedItems {
    # Gets customer protected items
    [CmdletBinding()]
    Param(        
    [Parameter(Mandatory = $true)] 
    [string]$customerID
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
            $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/backup/protectedItems" -Headers $requestHeaders
            $result | Add-Member -MemberType NoteProperty "customerID" -Value $customerID
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
    }
}
function Get-NMMCustomerRecoveryPoints {
    # Gets customer protected items
    [CmdletBinding()]
    Param(        
    [Parameter(Mandatory = $true,
        ValueFromPipeLine = $true,
        ValueFromPipelineByPropertyName = $true)] 
    [int]$customerID,
    [Alias("id")]
    [Parameter(Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
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
            $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/backup/recoveryPoints?protectedItemId=$($protectedItemId)" -Headers $requestHeaders
            $result | Add-Member -MemberType NoteProperty "customerID" -Value $customerID
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
    }
}
function Enable-NMMCustomerBackup {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [string]$sourceResourceId,
    [string]$backupPolicy,
    [int]$customerID
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
            $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/backup/enable" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Invoke-NMMCustomerRestore {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [string]$sourceResourceId,
    [string]$recoveryPointId,
    [int]$customerID
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
            $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/backup/restore" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Disable-NMMCustomerBackup {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [string]$sourceResourceId,
    [string]$protectedItemId,
    [int]$customerID,
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
            $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/backup/disable" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Invoke-NMMCustomerBackup {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [string]$sourceResourceId,
    [string]$protectedItemId,
    [int]$customerID
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
            $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/backup" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
#EndRegion Backup

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
            $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/costestimator/$($estimateID)" -Headers $requestHeaders
            $OK = $True
            }
            else{
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/costestimator/list" -Headers $requestHeaders
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
    }
}
#EndRegion Cost Estimator

#Region Directories
function Get-NMMDirectories {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $false)] 
    [int]$customerId
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
            if($customerId){
            $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/directories" -Headers $requestHeaders
            $OK = $True
            }
            else{
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/directories" -Headers $requestHeaders
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
    }
}
#EndRegion Directories

#Region FSLogix Configs
function Get-NMMFSlogixConfig {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [int]$customerId
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
            $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/fslogix" -Headers $requestHeaders
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
    }
}
#EndRegion FSLogix Configs

#Region Invoices
function Get-NMMInvoices {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [datetime]$startTime,
    [Parameter(Mandatory = $true)] 
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
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/invoices?periodStart=$($startTimeStr)&periodEnd=$($endTimeStr)&hidePaid=false&hideUnpaid=false" -Headers $requestHeaders
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
    }
}
function Get-NMMInvoicesUnpaid {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [datetime]$startTime,
    [Parameter(Mandatory = $true)] 
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
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/invoices?periodStart=$($startTimeStr)&periodEnd=$($endTimeStr)&hidePaid=true&hideUnpaid=false" -Headers $requestHeaders
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
    }
}
function Get-NMMInvoicesPaid {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [datetime]$startTime,
    [Parameter(Mandatory = $true)] 
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
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/invoices?periodStart=$($startTimeStr)&periodEnd=$($endTimeStr)&hidePaid=false&hideUnpaid=true" -Headers $requestHeaders
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
    }
}

function Get-NMMInvoiceID {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
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
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/invoices/$($invoiceId)" -Headers $requestHeaders
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
    }
}
#EndRegion Invoices

#Region Jobs
function Get-NMMJob {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
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
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/job/$($jobId)" -Headers $requestHeaders
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
    }
}
function Get-NMMJobTasks {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
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
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/job/$($jobId)/tasks" -Headers $requestHeaders
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
    }
}
function Restart-NMMJob {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
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
                $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/job/$($jobId)" -Headers $requestHeaders
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
    }
}

#EndRegion Jobs

#Region Networks
function Get-NMMManagedNetworks {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $false)] 
    [int]$customerId
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
            $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/networks" -Headers $requestHeaders
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
    }
}
function Get-NMMAllNetworks {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $false)] 
    [int]$customerId
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
            $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/networks/all" -Headers $requestHeaders
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
    }
}
function Register-NMMNetwork {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [int]$customerId,
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
            $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/networks/link" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}

#EndRegion Networks

#Region Scripted Actions
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
        $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/scripted-actions" -Headers $requestHeaders
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
    }
}
function Remove-NMMScriptedAction {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [int]$id
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
        $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/scripted-actions" -Headers $requestHeaders
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
    }
}
#EndRegion Scripted Actions

#Region Resource Group
function Get-NMMResourceGroup {
    # Pulls RGs linked to the MSP's NMM instance, unless using the -customerID flag.
    [CmdletBinding()]
    Param(        
    [Parameter(Mandatory = $false)] 
    [string]$customerID
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
        
            if($customerId){
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/resource-group" -Headers $requestHeaders
                $OK = $True
            }
            else {
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/resource-group" -Headers $requestHeaders
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
    }
}
function Remove-NMMResourceGroup {
    # Removed specified RG from the MSP's NMM instance, unless using the -customerID flag.
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [string]$subscriptionId,
    [string]$resourceGroup,
    [Parameter(Mandatory = $false)] 
    [string]$customerID
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
        
            if($customerId){
                $result = Invoke-RestMethod -Method DELETE -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/resource-group/linked" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
                $OK = $True
            }
            else {
                $result = Invoke-RestMethod -Method DELETE -Uri "https://$nmmBaseUri/rest-api/v1/resource-group/linked" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Register-NMMResourceGroup {
    # Registers an RG from the MSP's NMM instance, unless using the -customerID flag.
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [string]$subscriptionId,
    [string]$resourceGroup,
    [Parameter(Mandatory = $false)] 
    [string]$customerID
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
        
            if($customerId){
                $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/resource-group/linked" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
                $OK = $True
            }
            else {
                $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/resource-group/linked" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Set-DefaultNMMResourceGroup {
    # Set specified RG from the MSP's NMM instance as default, unless using the -customerID flag.
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [string]$subscriptionId,
    [string]$resourceGroup,
    [Parameter(Mandatory = $false)] 
    [string]$customerID
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
        
            if($customerId){
                $result = Invoke-RestMethod -Method PUT -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/resource-group/setDefault" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
                $OK = $True
            }
            else {
                $result = Invoke-RestMethod -Method PUT -Uri "https://$nmmBaseUri/rest-api/v1/resource-group/setDefault" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
#EndRegion Resource Group

#Region Secure Variables
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
        $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/secure-variables" -Headers $requestHeaders
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
    }
}
function New-NMMSecureVariable {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
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
        $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Update-NMMSecureVariable {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
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
        $result = Invoke-RestMethod -Method PUT -Uri "https://$nmmBaseUri/rest-api/v1/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Remove-NMMSecureVariable {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
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
        $result = Invoke-RestMethod -Method DELETE -Uri "https://$nmmBaseUri/rest-api/v1/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
function Get-NMMCustomerSecureVariable {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [int]$customerID,
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
        $customers = Get-NMMCustomers
        $searchResults = $null
        if($customerID){
            $customerData = $customers | Where-Object id -match $customerID
            Write-Host "Querying NMM for all Scripted Actions for $($customerData.name) (ID: $($customerData.id))"
        }
        if($customerSearch) {
            $searchResults = $customers | Where-Object name -match $customerSearch
            if ($searchResults.Count -eq 1){
                Write-Host "Match found! Querying NMM for all Scripted Actions for customer $($searchResults.name) using ID $($searchResults.id)"
                $customerid = $($searchResults.id)
            }
            if ($searchResults.Count -gt 1){
                $searchResults | Format-Table
                [int]$customerSelection = Read-Host "Multiple customers found matching ""$customerSearch"", please select your customer ID" 
                $customerid = $customerSelection 
            }
            elseif ($searchResults.Count -gt 10){
                Write-Host "Too many results matching $customerSearch, please try again with more specificity."
            }
        }
    }
    PROCESS {
        Try{
        $customerVars = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerid)/secure-variables" -Headers $requestHeaders
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
            # Write-Output "Secure Vars for $($customerid)"
            Write-Output $customerVars
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
    }
}
function New-NMMCustomerSecureVariable {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [int]$customerID,
        [Parameter(Mandatory = $false,
        ValueFromPipeline = $false)]
        [String]$customerSearch,
        [Parameter(Mandatory = $true)]
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
        $customers = Get-NMMCustomers
        $searchResults = $null
        if($customerSearch) {
            $searchResults = $customers | Where-Object name -match $customerSearch
            if ($searchResults.Count -eq 1){
                $customerid = $($searchResults.id)
            }
            if ($searchResults.Count -gt 1){
                $searchResults | Format-Table
                [int]$customerSelection = Read-Host "Multiple customers found matching ""$customerSearch"", please enter your customer ID" 
                $customerid = $customerSelection 
            }
            elseif ($searchResults.Count -gt 10){
                Write-Host "Too many results matching $customerSearch, please try again with more specificity."
            }
        }
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
        $customerVars = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerid)/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
            # Write-Output "Secure Vars for $($customerid)"
            Write-Output $customerVars
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
    }
}
function Update-NMMCustomerSecureVariable {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [int]$customerID,
        [Parameter(Mandatory = $false,
        ValueFromPipeline = $false)]
        [String]$customerSearch,
        [Parameter(Mandatory = $true)]
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
        $customers = Get-NMMCustomers
        $searchResults = $null
        if($customerSearch) {
            $searchResults = $customers | Where-Object name -match $customerSearch
            if ($searchResults.Count -eq 1){
                $customerid = $($searchResults.id)
            }
            if ($searchResults.Count -gt 1){
                $searchResults | Format-Table
                [int]$customerSelection = Read-Host "Multiple customers found matching ""$customerSearch"", please enter your customer ID" 
                $customerid = $customerSelection 
            }
            elseif ($searchResults.Count -gt 10){
                Write-Host "Too many results matching $customerSearch, please try again with more specificity."
            }
        }
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
        $customerVars = Invoke-RestMethod -Method PUT -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerid)/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
            # Write-Output "Secure Vars for $($customerid)"
            Write-Output $customerVars
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
    }
}
function Remove-NMMCustomerSecureVariable {
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [int]$customerID,
        [Parameter(Mandatory = $false,
        ValueFromPipeline = $false)]
        [String]$customerSearch,
        [Parameter(Mandatory = $true)]
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
        $customers = Get-NMMCustomers
        $searchResults = $null
        if($customerSearch) {
            $searchResults = $customers | Where-Object name -match $customerSearch
            if ($searchResults.Count -eq 1){
                $customerid = $($searchResults.id)
            }
            if ($searchResults.Count -gt 1){
                $searchResults | Format-Table
                [int]$customerSelection = Read-Host "Multiple customers found matching ""$customerSearch"", please enter your customer ID" 
                $customerid = $customerSelection 
            }
            elseif ($searchResults.Count -gt 10){
                Write-Host "Too many results matching $customerSearch, please try again with more specificity."
            }
        }
        $requestBody = @(@"
        {
            "name": "$($variableName)"
        }
"@)
    }
    PROCESS {
        Try{
        $customerVars = Invoke-RestMethod -Method DELETE -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerid)/secure-variables" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
            # Write-Output "Secure Vars for $($customerid)"
            Write-Output $customerVars
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
    }
}
#EndRegion Secure Variables

#Region Usage
function Get-NMMUsage {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [datetime]$startTime,
    [Parameter(Mandatory = $true)] 
    [datetime]$endTime,
    [Parameter(Mandatory = $true)] 
    [bool]$withDetails,
    [Parameter(Mandatory = $false)]
    [int]$customerId 
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
                if($customerId){
                    $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/usages?startDate=$($startTimeStr)&endDate=$($endTimeStr)&withDetails=$($withDetails)" -Headers $requestHeaders
                    $OK = $True
                }
                else{
                $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/usages?startDate=$($startTimeStr)&endDate=$($endTimeStr)&withDetails=$($withDetails)" -Headers $requestHeaders
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
    }
}
#EndRegion Usage

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
        $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/app-role-assignments" -Headers $requestHeaders
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
        $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/app-role-assignments/roles" -Headers $requestHeaders
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
    }
}
#EndRegion App Role Assignments

#Region Workspace
function Get-NMMCustomerWorkspace {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [string]$customerID
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
        $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/workspace" -Headers $requestHeaders
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
    }
}
function New-NMMCustomerWorkspace {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
    [int]$customerID,
    [Parameter(Mandatory = $true)] 
    [string]$region,
    [Parameter(Mandatory = $true)] 
    [string]$resourceGroup,
    [Parameter(Mandatory = $true)] 
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
        $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/workspace" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
    }
}
#EndRegion Workspace