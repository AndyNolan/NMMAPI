$nmmConfig = "$($env:USERPROFILE)\NMMAPI\nmmConfig.json"

function Export-NMMCredentials {
    [CmdletBinding()]
    Param()
    BEGIN {
        if ($nmmBaseUri -and $nmmOauth -and $nmmTenantId -and $nmmClientId -and $nmmScope -and $nmmSecret){
            $ssConvert = $nmmSecret | ConvertFrom-SecureString
            New-Item -ItemType Directory -Force -Path $nmmConfig
            $begin = Get-Date
            $OK = $true
        } else{
            Write-Host "Missing one or more REST API credentials. Please run Add-NMMCredentials and try again."
        }
}
    PROCESS {
        if ($OK = $true){
        $exportCreds = @(@"
{
            "nmmBaseUri":   "$nmmBaseUri",
            "nmmOauth":   "$nmmOauth",
            "nmmTenantId":   "$nmmTenantId",
            "nmmClientId":   "$nmmClientId",
            "nmmScope":   "$nmmScope",
            "nmmSecret":   "$ssConvert"
}
"@)
        $exportCreds | Out-File -FilePath $nmmConfig -Force
    } else {
        Write-Error "Unable to output API configuration settings to $nmmConfig"
    }    
}
}
