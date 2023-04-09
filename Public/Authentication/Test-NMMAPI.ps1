function Test-NMMAPI {
    [CmdletBinding()]
    Param()
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
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/test" -Headers $requestHeaders
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
            Write-Host "Successfully connected to the NMM API located at $nmmBaseUri!"
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
        
    }
}
