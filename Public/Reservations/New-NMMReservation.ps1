function New-NMMReservation{
    [CmdletBinding()]
    Param (
        [Alias("id")]
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [int]$customerID,
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
        $newVault = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerid)/reservations" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
