@(
    # Import public functions
    Get-ChildItem -Recurse -Path $PSScriptRoot\Public\*.ps1
).foreach{ try { . $_.FullName } catch { throw $_ }}

# Check for existing credential file and import
Import-NMMCredentials