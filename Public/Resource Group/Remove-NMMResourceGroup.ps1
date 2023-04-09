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
        Write-Verbose "Execution completed in $runtime"
    }
}
