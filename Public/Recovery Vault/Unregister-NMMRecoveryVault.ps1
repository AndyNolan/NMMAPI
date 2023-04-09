function Unregister-NMMRecoveryVault{
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
        $vaultValidation = Get-NMMAllRecoveryVaults -customerId $customerID | Where-Object id -match $vaultID
        
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
        $newVault = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerid)/recovery-vault/unlink/vault?vaultId=$($matchedVaultId)" -Headers $requestHeaders
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
