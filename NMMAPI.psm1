@(
    # Import public functions
    Get-ChildItem -Recurse -Path $PSScriptRoot\Public\*.ps1
).foreach{ try { . $_.FullName } catch { throw $_ }}