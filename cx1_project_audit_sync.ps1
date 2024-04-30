param (
    [Parameter(Mandatory=$true)][string]$Cx1_URL,
    [Parameter(Mandatory=$true)][string]$IAM_URL,
    [Parameter(Mandatory=$true)][string]$Tenant,
    [Parameter(Mandatory=$true)][string]$APIKey,
    [Parameter(Mandatory=$true)][string]$SourceScan,
    [Parameter(Mandatory=$true)][string]$DestScan
)


function GetTokenHeaders {
    #Get Access token
    $uri = $IAM_URL + "/auth/realms/" + $Tenant+ "/protocol/openid-connect/token"
    $params = @{
      grant_type = "refresh_token"
      client_id = "ast-app"  
      refresh_token = $APIKey
    }
    $access_token = (Invoke-RestMethod $uri -Method POST -Body $params).access_token
    #Create Headers
    $headers = @{
      accept = "application/json; version=1.0"
      Authorization = "Bearer $access_token"
    }
    return $headers
}

function GetTotalResults {
    param (
        [string]$ScanID
    )
    $uri = $Cx1_URL + "/api/results/?scan-id=" + $ScanID + "&limit=0"
    $results = (Invoke-RestMethod $uri -Method GET -Headers $headers)
    
    return $results.totalCount
}

function AddResultsPredicate {
    param ($rp)
    $uri = $Cx1_URL + "/api/sast-results-predicates/"
    #Write-Host "Adding results predicate: "
    #$rp
    
    $response = (Invoke-RestMethod $uri -Method POST -Headers $headers -body "[$($rp | ConvertTo-Json)]" )
    #$response

}

$headers = GetTokenHeaders
$total = GetTotalResults $SourceScan
$uri = $Cx1_URL + "/api/results/?scan-id=" + $SourceScan + "&limit=$total"
Write-Host $uri
$srcResults = (Invoke-RestMethod $uri -Method GET -Headers $headers).results

$total = GetTotalResults $DestScan
$uri = $Cx1_URL + "/api/results/?scan-id=" + $DestScan + "&limit=$total"
Write-Host $uri
$dstResults = (Invoke-RestMethod $uri -Method GET -Headers $headers).results

$uri = $Cx1_URL + "/api/scans/" + $DestScan
$DestProjectID = (Invoke-RestMethod $uri -Method GET -Headers $headers).projectId

$matchCount = 0

$srcResults | foreach-object {
    $id++
    $src = $_
    $dstResults | foreach-Object {
        $dst = $_
        if ($src.similarityId -eq $dst.similarityId) {
            Write-Host "`nMatched finding: $($src.similarityId) - $($src.data.queryName) in $($src.data.nodes[0].filename):$($src.data.nodes[0].line)"      
                  
            $rp = @{
                similarityId = $src.similarityId
                projectId = $DestProjectID
                comment = "project_audit_sync"
                severity = $src.severity
                state = $src.state.Trim()
            }
            
            if ($src.state -ne $dst.state -or $src.severity -ne $dst.severity ) {
            
                if ($src.state -ne $dst.state) {
                    Write-Host "`t- changed: $($src.state) vs $($dst.state)"
                }
                if ($src.severity -ne $dst.severity) {
                    Write-Host "`t- changed: $($src.severity) vs $($dst.severity)"
                }                
                AddResultsPredicate @($rp)
                $matchCount ++
            } else {
                Write-Host "`tSame state & severity, no update needed"
            }
                      
        }
    }
}

Write-Host "$matchCount findings updated"