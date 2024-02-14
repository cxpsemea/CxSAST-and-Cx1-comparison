param (
    [Parameter(Mandatory = $false)][string]$SASTReportXML = "",
    [Parameter(Mandatory = $false)][string]$SASTUrl = "",
    [Parameter(Mandatory = $false)][string]$SASTUser = "",
    [Parameter(Mandatory = $false)][string]$SASTPassword = "",
    [Parameter(Mandatory = $false)][int]$SASTScanID = 0,
    [Parameter(Mandatory = $true)][string]$Cx1Url,
    [Parameter(Mandatory = $true)][string]$IAMUrl,
    [Parameter(Mandatory = $true)][string]$Cx1Tenant,
    [Parameter(Mandatory = $false)][string]$Cx1APIKey = "",
    [Parameter(Mandatory = $false)][string]$Cx1ClientID = "",
    [Parameter(Mandatory = $false)][string]$Cx1ClientSecret = "",
    [Parameter(Mandatory = $true)][string]$Cx1ScanID
)

Set-StrictMode -Version 2
$logfile = "compare-log.txt"

if ( Test-Path $logfile ) {
    Clear-Content $logfile
}

# Get timestamp for Logs
function getTime() {
    return "[{0:MM/dd/yyyy} {0:HH:mm:ss.fff K}]" -f (Get-Date)
}

#log message to Console
function log($message, $warning = $false) {
    $formattedMessage = "$(getTime) ${message}"
    if(!$warning){
        Write-Host $formattedMessage
    } else{
        Write-Warning $formattedMessage
    }
    
    $formattedMessage | Out-File $logfile -Append
}

function req($uri, $method, $token, $errorMessage, $body){
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json;v=1.0"
        "Accept" = "application/json; version=1.0"
    }
    try {
        if($method -eq "POST" -or $method -eq "PUT"){
            $body = $body | ConvertTo-Json
            $resp = Invoke-RestMethod -uri $uri -method $method -headers $headers -body $body #-Proxy "http://127.0.0.1:8080"
        } else {
            $resp = Invoke-RestMethod -uri $uri -method $method -headers $headers #-Proxy "http://127.0.0.1:8080"
        }
        return $resp
    } catch {
        log $_
        $value = $_.Exception.Response.StatusCode.value__
        $description = $_.Exception.Response.StatusDescription
        log "StatusCode: ${value}" 
        log "StatusDescription: ${description}" 
        log "Request body was: $($body | ConvertTo-Json)"
        throw $errorMessage
    }
}

function shorten($str) {
    return $str.Substring(0,4) +".."+ $str.Substring($str.length - 4)
}


$contentType = "text/xml; charset=utf-8"
$openSoapEnvelope = '<?xml version="1.0" encoding="utf-8"?><soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"><soap12:Body>'
$closeSoapEnvelope = '</soap12:Body></soap12:Envelope>'
$actionPrefix = 'http://Checkmarx.com'

######## Login ########
function getSASTSoapToken($server, $username, $password){
    $body = @{
        username = $username
        password = $password
        grant_type = "password"
        scope = "offline_access sast_api"
        client_id = "resource_owner_sast_client"
        client_secret = "014DF517-39D1-4453-B7B3-9930C563627C"
    }
    
    try {
        $response = Invoke-RestMethod -uri "${server}/cxrestapi/auth/identity/connect/token" -method post -body $body -contenttype 'application/x-www-form-urlencoded'
    } catch {
        throw "Could not authenticate user ${username}: $($_.Exception.Response.StatusDescription)"
    }
    
    return $response.token_type + " " + $response.access_token
}
######## Get Headers ########
function getHeaders($token, $action){
    return @{
        Authorization = $token
        "SOAPAction" = "${actionPrefix}/${action}"
        "Content-Type" = $contentType
    }
}
######## Get Queries for a Scan ########
function getQueriesForScan($url, $token, $scanId){
    #log "SOAP - getQueriesForScan for scan $scanId"
    
    $payload = $openSoapEnvelope +'<GetQueriesForScan xmlns="http://Checkmarx.com">
                      <sessionID></sessionID>
                      <scanId>' + $scanId + '</scanId>
                    </GetQueriesForScan>' + $closeSoapEnvelope
    
    $headers = getHeaders $token "GetQueriesForScan"
    
    [xml]$res = Invoke-WebRequest "$($url)/CxWebInterface/Portal/CxWebService.asmx" -Method POST -Body $payload -Headers $headers #-Proxy "http://127.0.0.1:8080"
    
    $res1 = $res.Envelope.Body.GetQueriesForScanResponse.GetQueriesForScanResult
    #writeXML($res1)
    if($res1.IsSuccesfull){
        return $res1.Queries.ChildNodes
    } 
    else {
        throw $res1.ErrorMessage
    }
}

######## Get Results for a Query for a Scan ########
function getScanResultsForQuery($url, $token, $scanId, $queryId ){
    #log "SOAP - getResultsForQuery for scan $scanId and query $queryId"     
    $payload = $openSoapEnvelope +'<GetResultsForQuery xmlns="http://Checkmarx.com">
                      <sessionID></sessionID>
                      <scanId>' + $scanId + '</scanId>
                      <queryId>' + $queryId + '</queryId>
                    </GetResultsForQuery>' + $closeSoapEnvelope
    
    $headers = getHeaders $token "GetResultsForQuery"
    
    [xml]$res = Invoke-WebRequest "$($url)/CxWebInterface/Portal/CxWebService.asmx" -Method POST -Body $payload -Headers $headers #-Proxy "http://127.0.0.1:8080"
    $res1 = $res.Envelope.Body.GetResultsForQueryResponse.GetResultsForQueryResult
    
    #writeXML($res1)
    if($res1.IsSuccesfull){
        return $res1.Results.ChildNodes
    } 
    else {
        throw $res1.ErrorMessage
    }
}

######## Get Path Nodes for a Result ########
function getPathForResult($url, $token, $scanId, $pathId ){
    #log "SOAP - getResultPath for scan $scanId and path $pathId"     
    $payload = $openSoapEnvelope +'<GetResultPath xmlns="http://Checkmarx.com">
                      <sessionId></sessionId>
                      <scanId>' + $scanId + '</scanId>
                      <pathId>' + $pathId + '</pathId>
                    </GetResultPath>' + $closeSoapEnvelope
    
    $headers = getHeaders $token "GetResultPath"
    
    [xml]$res = Invoke-WebRequest "$($url)/CxWebInterface/Portal/CxWebService.asmx" -Method POST -Body $payload -Headers $headers #-Proxy "http://127.0.0.1:8080"
    $res1 = $res.Envelope.Body.GetResultPathResponse.GetResultPathResult
    
    #writeXML($res1)
    if($res1.IsSuccesfull){
        return [array]$res1.Path.Nodes.ChildNodes
    } 
    else {
        throw $res1.ErrorMessage
    }
}


function getCx1APIToken( $iam, $tenant, $apikey ) {
    $uri = "$($iam)/auth/realms/$($tenant)/protocol/openid-connect/token"
    $body = @{
        client_id = "ast-app"
        refresh_token = $apikey
        grant_type = "refresh_token"
    } 
    try  {
        $resp = Invoke-RestMethod -uri $uri -method "POST" -body $body #-Proxy "http://127.0.0.1:8080"
        return $resp.access_token
    } catch {
        log $_
        $value = $_.Exception.Response.StatusCode.value__
        $description = $_.Exception.Response.StatusDescription
        log "StatusCode: ${value}" 
        log "StatusDescription: ${description}" 
        log "Request body was: $($body | ConvertTo-Json)"
        throw $errorMessage
    }
}
function getCx1OIDCToken( $iam, $tenant, $client_id, $client_secret ) {
    $uri = "$($iam)/auth/realms/$($tenant)/protocol/openid-connect/token"
    $body = @{
        client_id = $client_id
        client_secret = $client_secret
        grant_type = "client_credentials"
    } 
    try  {
        $resp = Invoke-RestMethod -uri $uri -method "POST" -body $body
        return $resp.access_token
    } catch {
        log $_
        log "Request body was: $($body | ConvertTo-Json)"
        throw "Failed to authenticate to cx1"
    }
}

function getCx1ScanResults( $url, $token, $scanId ) {
    $headers = @{
        accept = "application/json; version=1.0"
        Authorization = "Bearer $token"
    }

    $uri = $url + "/api/results/?scan-id=" + $scanId + "&limit=0"
    $resultsCount = (Invoke-RestMethod $uri -Method GET -Headers $headers).totalCount

    $uri = $url + "/api/results/?scan-id=" + $scanId + "&limit=$resultsCount" # maybe change to do paging? is there a response size limit?
    $results = (Invoke-RestMethod $uri -Method GET -Headers $headers).results
    return $results
}

## Comparison functions

$matchNodeCountDeviation = 1

function CompareNodes( $Cx1, $SAST ) {
    if ( $Cx1.line -eq $SAST.Line -and `
         $Cx1.name -imatch $SAST.Name -and `
         $Cx1.column -eq $SAST.Column -and `
         $Cx1.fileName -imatch $SAST.FileName ) {
        return $true
    }
    return $false
}
function FindMatch( $Cx1Finding, $SASTFindings ) {
    #log "Checking Cx1 finding: $($Cx1Finding.data.languageName) - $($Cx1Finding.data.group) - $($Cx1Finding.data.queryName) [$($Cx1Finding.similarityId)]"

    for ( $i = 0; $i -lt $SASTFindings.length; $i++ ) {
        #Write-Host " - $i"
        $sf = $SASTFindings[$i]
        #log " - SAST finding $($i): $($sf.query.language) - $($sf.query.group) - $($sf.query.name) [$($sf.similarityID)]"
        if ( $sf.Match -eq $false -and
             $sf.query.name -imatch $Cx1Finding.data.queryName -and  `
             $sf.query.group -imatch $Cx1Finding.data.group -and `
             $sf.query.language -imatch $Cx1Finding.data.languageName ) {
            #Write-Host " - Finding type match: $($sf.Language) - $($sf.Group) - $($sf.Name)"
            #Write-Host " - SAST finding has $($sf.Nodes.length) nodes vs $($Cx1Finding.data.nodes.length) in Cx1"
            $nodeDiff = $sf.Nodes.length - $Cx1Finding.data.nodes.length
            if ( $nodeDiff -gt -1*$matchNodeCountDeviation -and $nodeDiff -lt $matchNodeCountDeviation ) { # +/- 1 difference
                if ( (CompareNodes $Cx1Finding.data.nodes[0] $sf.Nodes[0]) -and `
                     (CompareNodes $Cx1Finding.data.nodes[ $Cx1Finding.data.nodes.length - 1 ] $sf.Nodes[ $sf.Nodes.length - 1 ]) ) {
                    #Write-Host " - First and last nodes match"
                    $sf.Match = $true
                    return $sf
                }
            }
        }
    }

    return $null
}

##

$SASTResults = @()

###############
log "Starting result comparison:"
if ( $SASTReportXML -ne "" ) {
    if ( -Not (Test-Path -Path $SASTReportXML) ) {
        log "Error: the report file '$SASTReportXML' does not exist" $true
        return
    } else {
        $SASTResultsXML = [xml](Get-Content -Path $SASTReportXML)
        
        $SASTResultsXML.CxXMLResults.Query | foreach-object { 
            $query = [pscustomobject]@{
                id = $_.id
                name = $_.name
                language = $_.Language
                group = $_.group
            }

            $_.Result | foreach-object {
                $result = [pscustomobject]@{
                    query = $query
                    pathID = $_.Path.PathId
                    nodes = [array]$_.Path.PathNode
                    similarityID = $_.Path.SimilarityId
                    severity = $_.SeverityIndex
                    status = $_.StatusIndex
                    match = $false
                }
                $result.nodes | foreach-object {
                    $_.FileName = "/" + $_.FileName
                }

                
                
                $SASTResults += $result
            }
            

        }

        log "SAST results retrieved from file $SASTReportXML"
    }
} else {
    if ( $SASTUrl -eq "" -or $SASTUser -eq "" -or $SASTPassword -eq "" -or $SASTScanID -eq 0 ) {
        log "Error: Please provide the parameters:`n -SASTReportXML <file.xml> `nor`n -SASTUrl <url> -SASTUser <username> -SASTPassword <password> -SASTScanID <number>" , $true
        return
    }

    try {
        $SASTToken = getSASTSoapToken $SASTUrl $SASTUser $SASTPassword
        log "Authenticated successfully with user $SASTUser"

        $queries = getQueriesForScan $SASTUrl $SASTToken $SASTScanID
        if ( $queries -ne 0 -and $queries.Length -gt 0 ) {
            #writeXML( $queries )
            $queries | foreach-object {
            
                #log " -> QueryID: $($_.QueryID) - $($_.Name)"
                
                $results = getScanResultsForQuery $SASTUrl $SASTToken $SASTScanID $_.QueryID

                $query = [pscustomobject]@{
                    id = $_.QueryID
                    name = $_.QueryName
                    language = $_.LanguageName
                    group = $_.GroupName
                }

                $results | foreach-object {
                    $result = [pscustomobject]@{
                        query = $query
                        pathID = $_.PathId
                        nodes = getPathForResult $SASTUrl $SASTToken $SASTScanID $_.PathId
                        similarityID = $_.SimilarityId
                        severity = $_.Severity
                        status = $_.State
                        match = $false
                    }
                    $result.nodes | foreach-object {
                        $_.FileName = $_.FileName.Replace( '\', '/' )
                    }
                    
                    $SASTResults += $result
                }
            }
        }

        log "SAST results retrieved from $SASTUrl for scan ID: $SASTScanID"
    } catch {
        log "Error while getting results for scan $($SASTScanID): $_" $true
    }
}


log "CxSAST scan had $($SASTResults.Length) results"

<#
foreach ( $query in $SASTResults ) {
    log "Query id: $($query.Query.id)"
    foreach ( $result in $query.Results ) {
        log "Result: $($result.pathID)"
        $result.nodes
    }
}#>


$Cx1Results = @()
if ( $IAMUrl -eq "" -or $Cx1Url -eq "" -or $Cx1Tenant -eq "" -or $Cx1ScanID -eq "" -or ( $Cx1APIKey -eq "" -and ( $Cx1ClientSecret -eq "" -or $Cx1ClientID -eq "" ) ) ) {
    log "Error: Please provide the parameters:
 -IAMUrl <eu.iam.checkmarx.net> -Cx1Url <eu.ast.checkmarx.net> -Cx1ScanID <scan_id> -Cx1ClientID <client_id> -Cx1ClientSecret <client_secret>`nor
 -IAMUrl <eu.iam.checkmarx.net> -Cx1Url <eu.ast.checkmarx.net> -Cx1ScanID <scan_id> -Cx1APIKey <apikey>`n"  $true
    return
} else {
    try {
        if ( $Cx1APIKey -ne "" ) {
            $Cx1Token = getCx1APIToken $IAMUrl $Cx1Tenant $Cx1APIKey
            log "Authenticated successfully with APIKey"
        } else {
            $Cx1Token = getCx1OIDCToken $IAMUrl $Cx1Tenant $Cx1ClientID $Cx1ClientSecret
            log "Authenticated successfully with client $Cx1ClientID"
        }

        $Cx1Results = getCx1ScanResults $Cx1Url $Cx1Token $Cx1ScanID
        log "Cx1 scan results retrieved from $Cx1Url for ScanID $Cx1ScanID"
    } catch {
        log $_ $true
        return
    }
}

log "Cx1 scan had $($Cx1Results.Length) results"
log ""
log "================= Comparing results ================="

$matching = @()
$new_cx1 = @()
$missing_cx1 = @()

foreach ( $cx1finding in $Cx1Results ) {
    if ( -Not ($cx1finding.data.PSObject.Properties.name -contains "languageName") ){
        $cx1finding.data | Add-Member -NotePropertyName "languageName" -NotePropertyValue ""
    }
    if ( -Not ($cx1finding.data.PSObject.Properties.name -contains "resultHash") ){
        $cx1finding.data | Add-Member -NotePropertyName "resultHash" -NotePropertyValue ""
    }
    $match = FindMatch $cx1finding $SASTResults
    if ( $null -eq $match ) {
        $new_cx1 += $cx1finding
    } else {
        $matching += [pscustomobject]@{
            cx1 = $cx1finding
            sast = $match
        }
    }
}

foreach ( $sastfinding in $SASTResults ) {
    if ( -Not $sastfinding.match ) {
        $missing_cx1 += $sastfinding
    }
}

log "Comparing $($SASTResults.Length) results from SAST with $($Cx1Results.Length) results from Cx1:"
log "`t$($matching.Length) results match" $true
log "`t$($new_cx1.Length) results are new in Cx1" $true
log "`t$($missing_cx1.Length) results from SAST are missing in Cx1" $true

log ""
log "================= Comparison ================="

if ( $matching.Length -gt 0 ) {
    log ""
    log "The following results match:"

    foreach ( $match in $matching | Sort-Object -Property {$_.sast.query.language},{$_.sast.query.group},{$_.sast.query.name},{$_.sast.similarityId},{$_.sast.pathID} ) {
        log "`t- $($match.cx1.type): $($match.sast.query.language) - $($match.sast.query.group) - $($match.sast.query.name): SAST [SimID $($match.sast.similarityId), PathID: $($match.sast.pathID)], Cx1 [SimID: $($match.cx1.similarityId), ResultHash: $($match.cx1.data.resultHash)]"
    }
}

if ( $missing_cx1.Length -gt 0 ) {
    log ""
    log "The following results were in SAST, but are not in Cx1:" $true

    foreach ( $miss in $missing_cx1 | Sort-Object -Property {$_.query.language},{$_.query.group},{$_.query.name},{$_.similarityId},{$_.pathID} ) {
        log "`t- sast: $($miss.query.language) - $($miss.query.group) - $($miss.query.name): SAST [SimID $($miss.similarityId), PathID: $($miss.pathID)]"
    }
}

if ( $new_cx1.Length -gt 0 ) {
    log ""
    log "The following results are new in Cx1:" $true

    foreach ( $newf in $new_cx1 | Sort-Object -Property {$_.data.languageName},{$_.data.group},{$_.data.queryName},{$_.similarityId},{$_.data.resultHash}) {
        log "`t- $($newf.type): $($newf.data.languageName) - $($newf.data.group) - $($newf.data.queryName): Cx1 [SimID: $($newf.similarityId), ResultHash: $($newf.data.resultHash)]"
#            log "`t- $($newf.type): $($newf.data.group) - $($newf.data.queryName): Cx1 [SimID: $($match.cx1.similarityId), ResultHash: $($match.cx1.data.resultHash)]"
    }
}





log ""
log "================= Information ================="

if ( $new_cx1.Length -gt 0 -or $missing_cx1.Length -gt 0 ) {
    log "Results may be different for the following reasons:"
    log "`t- Different presets used, or different queries in the preset"
    log "`t- Different engine versions in CxSAST vs CheckmarxOne, which may include renamed findings"
    log "`t- Different configurations, or customized configurations in CxSAST"
    log "`t- Different queries, customized in CxSAST or CheckmarxOne"
    log "`t- Different file/folder exclusions configured in CxSAST vs CheckmarxOne"
    log "`t- Note that CheckmarxOne includes multiple engines (SCA, IAC, ...) which may produce new results not reported by the SAST engine"
}
