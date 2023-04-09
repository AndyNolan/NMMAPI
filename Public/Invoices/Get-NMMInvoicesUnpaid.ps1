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
        Write-Verbose "Execution completed in $runtime"
    }
}
