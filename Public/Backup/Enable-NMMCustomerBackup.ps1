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
        Write-Verbose "Execution completed in $runtime"
    }
}