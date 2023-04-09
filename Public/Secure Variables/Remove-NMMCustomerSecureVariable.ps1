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
        Write-Verbose "Execution completed in $runtime"
    }
}
