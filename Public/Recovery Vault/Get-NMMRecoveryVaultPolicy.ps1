function Get-NMMRecoveryVaultPolicy{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [int]$customerID,
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [String]$policyName,
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
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
        $customers = Get-NMMCustomers
        $searchResults = $null
        if($customerID){
            $customerData = $customers | Where-Object id -eq $customerID
            Write-Host "Querying NMM for all Recovery Vault policy $($policyName) for customer $($customerData.name) (ID: $($customerData.id))"
        }
    }
    PROCESS {
        Try{
        $customerVaultPolicy = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerid)/recovery-vault/policy?vaultId=$($vaultId)&policyName=$($policyName)" -Headers $requestHeaders
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
