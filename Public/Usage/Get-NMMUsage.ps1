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
        Write-Verbose "Execution completed in $runtime"
    }
}
