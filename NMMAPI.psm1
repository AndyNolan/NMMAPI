@(
    # Import public functions
    Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -Recurse
).foreach{ try { . $_.FullName } catch { throw $_ }}