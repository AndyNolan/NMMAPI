function Invoke-NMMScriptedAction {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)]
    [int]$scriptId,
    [int]$timeoutMins
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
        if($timeoutMins = $null){
            $timeoutMins = 30
        }
        $defaultResourceGroup = (Get-NMMResourceGroup | Where-Object isDefault -eq True).name
        $requestBody = @(@"
        {
            "adConfigId": null,
            "paramsBindings": {
              "ResourceGroup": {
                "value": "$($defaultResourceGroup)",
                "isSecure": false
              }
            },
            "minutesToWait": 30
          }
"@)
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Method POST -Uri "https://$nmmBaseUri/rest-api/v1/scripted-actions/$($scriptId)/execution" -Headers $requestHeaders -Body $requestBody -ContentType "application/json"
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
