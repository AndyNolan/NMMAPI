function Get-NMMToken {

    if (!$nmmBaseURI -or !$nmmOauth -or !$nmmTenantId -or !$nmmClientId -or !$nmmScope -or !$nmmSecret) {
        Write-Error "One or more configuration variables are missing. Please run Add-NMMCredentials to re-add and try again."
    }
    else{
    $tokenSplat = @{
        grant_type = "client_credentials";
        client_secret = ($nmmSecret | ConvertFrom-SecureString -AsPlainText);
        client_id = $nmmClientId;
        scope = $nmmScope;
        }
        $nmmOAToken = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$($nmmTenantId)/oauth2/v2.0/token" -Method POST -Body $tokenSplat
        Set-Variable -Name 'nmmTokenExp' -Value (Get-Date).AddMinutes(59) -Scope Global
        Set-Variable -Name 'nmmToken' -Value $nmmOAToken -Scope Global
    }
}
