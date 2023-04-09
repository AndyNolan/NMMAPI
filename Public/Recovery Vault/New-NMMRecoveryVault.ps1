function New-NMMRecoveryVault{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [int]$customerID,
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
        $rgValidation = Get-NMMResourceGroup -customerId $customerID | Where-Object name -match $resourceGroup
        
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
        $newVault = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerid)/recovery-vault" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
