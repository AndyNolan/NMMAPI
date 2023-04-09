function Add-NMMCredentials {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true)]
        [String]
        $baseUri,
        $oAuthToken,
        $tenantId,
        $clientId,
        $scope,
        $secret
    )
    BEGIN {
        if (!$baseUri) {
            $baseUri = Read-Host -Prompt 'Please input your NMM URL, e.g. nmm.democompany.com'
        }
        if (!$oAuthToken) {
            $oAuthToken = Read-Host -Prompt 'Please input your OAuth 2.0 token'
        }
        if (!$tenantId) {
            $tenantId = Read-Host -Prompt 'Please input your tenant ID'
        }
        if (!$clientId) {
            $clientId = Read-Host -Prompt 'Please input your client ID'
        }
        if (!$scope) {
            $scope = Read-Host -Prompt 'Please input your scope'
        }
        if (!$secret) {
            $secret = Read-Host -Prompt 'Please input your secret'
        }
        Set-Variable -Name 'nmmBaseUri' -Value $baseUri -Scope Global 
        Set-Variable -Name 'nmmOauth' -Value $oAuthToken -Scope Global 
        Set-Variable -Name 'nmmTenantId' -Value $tenantId -Scope Global 
        Set-Variable -Name 'nmmClientId' -Value $clientId -Scope Global 
        Set-Variable -Name 'nmmScope' -Value $scope -Scope Global 
        Set-Variable -Name 'nmmSecret' -Value $($secret | ConvertTo-SecureString -AsPlainText -Force) -Scope Global 
    }
    PROCESS {
        Write-Host "Testing connectivity to the NMM API located at $nmmBaseUri..."
        Test-NMMAPI
    }
}
