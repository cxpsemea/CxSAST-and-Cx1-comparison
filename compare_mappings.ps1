param (
    [Parameter(Mandatory = $true)][string]$original,
    [Parameter(Mandatory = $true)][string]$custom
)

Set-StrictMode -Version 2

$original_map = (Get-Content $original) | ConvertFrom-Json
$custom_map = (Get-Content $custom) | ConvertFrom-Json

$sast_to_ast = @{}

$original_map.mappings | foreach-object {
    $sast_to_ast[$_.sastID] = $_.astID
}

$matches = @()
$differences = @()
$new = @()

$custom_map.mappings | foreach-object {
    if ( $sast_to_ast.ContainsKey( $_.sastID ) ) {
        if ( $sast_to_ast[$_.sastID] -eq $_.astID ) {
            $matches += $_
        } else {
            $differences += @{
                "sastID" = $_.sastID
                "original_astID" = $sast_to_ast[$_.sastID]
                "custom_astID" = $_.astID
                "origin" = $_.origin
            }
        }
    } else {
        $new += $_
    }
}

Write-Host "Compared $($original_map.mappings.Length) mappings in original with $($custom_map.mappings.Length) mappings in custom"
Write-Host "`tNew in custom: $($new.Length)"
Write-Host "`tMatching: $($matches.Length)"
Write-Host "`tDifferent: $($differences.Length)"

Write-Host ""
Write-Host "The following differences were found: "
Write-Host $differences

Write-Host ""
Write-Host "The following queries are new:"
Write-Host $new
