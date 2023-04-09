function Get-NMMHostPoolSessions{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [int]$customerID,
        [Alias("subscriptionId")]
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$subscription,
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$resourceGroup,
        [Alias("hostPoolName")]
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]$hostPool,
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
            $customerData = $customers | Where-Object id -eq $customerID
            Write-Host "Querying NMM for host pool ($($hostPool)) sessions for customer $($customerData.name) (ID: $($customerData.id))"
        }
        if($customerSearch) {
            $searchResults = $customers | Where-Object name -match $customerSearch
            if ($searchResults.Count -eq 1){
                Write-Host "Match found! Querying NMM for host pool ($($hostPool)) sessions for customer $($searchResults.name) using ID $($searchResults.id)"
                $customerid = $($searchResults.id)
            }
            if ($searchResults.Count -gt 1){
                $searchResults | Format-Table
                [int]$customerSelection = Read-Host "Multiple customers found matching ""$customerSearch"", please select your customer ID" 
                $customerid = $customerSelection 
            }
        }
    }
    PROCESS {
        Try{
        $hostPoolSessions = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerid)/host-pool/$($subscription)/$($resourceGroup)/$($hostPool)/sessions" -Headers $requestHeaders
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
