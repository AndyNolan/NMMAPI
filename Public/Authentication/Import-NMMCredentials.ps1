$nmmConfig = "$($env:USERPROFILE)\NMMAPI\nmmConfig.json"

function Import-NMMCredentials {
    [CmdletBinding()]
    Param()
    BEGIN {
        if(Test-Path $nmmConfig){
            $nmmCredentials = Get-Content -Path $nmmConfig -ErrorAction Stop
            $OK = $True
        } else{
            Write-Warning "Unable to validate NMM API config path at $nmmConfig. Run Add-NMMCredentials and input manually."
        }
}
    PROCESS {
        if ($OK = $true){
            $nmmImport = $nmmCredentials | ConvertFrom-Json

            Set-Variable -Name 'nmmBaseUri' -Value $nmmImport.nmmbaseUri -Scope Global 
            Set-Variable -Name 'nmmOauth' -Value $nmmImport.nmmOauth -Scope Global 
            Set-Variable -Name 'nmmTenantId' -Value $nmmImport.nmmTenantId -Scope Global 
            Set-Variable -Name 'nmmClientId' -Value $nmmImport.nmmClientId -Scope Global 
            Set-Variable -Name 'nmmScope' -Value $nmmImport.nmmScope -Scope Global 
            Set-Variable -Name 'nmmSecret' -Value $($nmmImport.nmmSecret | ConvertTo-SecureString) -Scope Global 

    } else {
        Write-Error "Unable to output API configuration settings to $($env:USERPROFILE)\NMMAPI\nmmConfig.json"
    }    
}
}
