function Get-NMMWorkspace {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory = $true)] 
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
        $begin = Get-Date
    }
    PROCESS {
        Try{
        $result = Invoke-RestMethod -Uri "https://$nmmBaseUri/rest-api/v1/accounts/$($customerId)/workspace" -Headers $requestHeaders
        $result | Add-Member -MemberType NoteProperty "customerId" -Value $($customerID)

        $betterOut = [PSCustomObject]@{
            nmmFriendlyName     = $($result.friendlyName)
            nmmDescription      = $($result.description)
            customerID          = $($result.customerId)
            subscriptionId      = $($result.id.subscriptionId)
            resourceGroup       = $($result.id.resourceGroup)
            workspaceName       = $($result.id.name)
        }
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
            Write-Output $betterOut
        }
    }
    END {
        $Runtime = New-TimeSpan -Start $begin -End (Get-Date)
        Write-Verbose "Execution completed in $runtime"
    }
}
