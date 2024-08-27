param (
    [Parameter(Mandatory = $true)][string]$SASTUrl,
    [Parameter(Mandatory = $true)][string]$SASTUser,
    [Parameter(Mandatory = $true)][string]$SASTPassword,
    [Parameter(Mandatory = $true)][string]$Cx1URL,
    [Parameter(Mandatory = $true)][string]$IAMUrl,
    [Parameter(Mandatory = $true)][string]$Cx1Tenant,
    [Parameter(Mandatory = $true)][string]$Cx1APIKey,
    [Parameter(Mandatory = $true)][string]$PresetName
)

Set-StrictMode -Version 2

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

function getSASTQueries($server, $token, $errorMessage){
    $payload = '<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <GetQueryCollection xmlns="http://Checkmarx.com">
                <i_SessionID></i_SessionID>
            </GetQueryCollection>
        </soap:Body>
    </soap:Envelope>'
        
    $headers = @{
        Authorization = "Bearer $token"
        "SOAPAction" = "http://Checkmarx.com/GetQueryCollection"
        "Content-Type" = "text/xml; charset=utf-8"
    }

    try {
        [xml] $res = Invoke-WebRequest "$server/CxWebInterface/Portal/CxWebService.asmx" -Method POST -Body $payload -Headers $headers #-Proxy "http://127.0.0.1:8080"
        $res1 = $res.Envelope.body.GetQueryCollectionResponse.GetQueryCollectionResult
        if($res1.IsSuccesfull){
            return $res1.QueryGroups            
        } else {
            $errorMessage = $res.ErrorMessage
            log "Error Retrieving SOAP Session from $server : $errorMessage}"
            throw "Cannot Get SOAP Session from $server"
        }
    } catch {
        $value = $_.Exception.Response.StatusCode.value__
        $description = $_.Exception.Response.StatusDescription
        log $_
        log "StatusCode: $value" 
        log "StatusDescription: $description" 
        throw "Cannot Get SOAP Session from $server"
    }
}

function getSASTPresets( $server, $token, $errormessage ) {
    $uri = "$($server)/cxrestapi/sast/presets"
    return req $uri "GET" $token $errormessage
}
function getSASTPresetDetails( $server, $token, $presetID, $errormessage ) {
    $uri = "$($server)/cxrestapi/sast/presets/$($presetID)"
    return req $uri "GET" $token $errormessage
}

function getCx1Queries( $server, $token, $errormessage ) {
    $uri = "$($server)/api/cx-audit/queries"
    return req $uri "GET" $token $errormessage
}

function getCx1QueryMappings( $server, $token, $errormessage ) {
    $uri = "$($server)/api/queries/mappings"
    return req $uri "GET" $token $errormessage
} 

function getCx1PresetByName( $server, $token, $presetName, $errormessage ) {
    $uri = "$($server)/api/presets?name=$($presetName)"
    return req $uri "GET" $token $errormessage
}

function getCx1PresetDetails( $server, $token, $presetID, $errormessage) {
    $uri = "$($server)/api/presets/$($presetID)"
    return req $uri "GET" $token $errormessage
}

function getSASTToken($server, $user, $pwd, $isSoap = $false){
    $body = @{
        username = $user
        password = $pwd
        grant_type = "password"
        scope = "sast_rest_api"
        client_id = "resource_owner_client"
        client_secret = "014DF517-39D1-4453-B7B3-9930C563627C"
    }
        
    if($isSoap){
        $body.scope = "offline_access sast_api"
        $body.client_id = "resource_owner_sast_client"
    }

    try {
        $response = Invoke-RestMethod -uri "${server}/cxrestapi/auth/identity/connect/token" -method post -body $body -contenttype 'application/x-www-form-urlencoded' #-Proxy "http://127.0.0.1:8080"
    } catch {
        $value = $_.Exception.Response.StatusCode.value__
        $description = $_.Exception.Response.StatusDescription
        log "StatusCode:  ${value}" 
        log "StatusDescription:  ${description}" 
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
        log $responseBody
        throw "Could not authenticate - User: ${user}"
    }
    
    return $response.access_token
}

function getCx1Token( $iam, $tenant, $apikey ) {
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

function addQuery( $queries, $level, $language, $group, $query, $id ) {
    if ( -Not $queries.ContainsKey( $language ) ) {
        $queries[$language] = @{}
    }
    if ( -Not $queries[$language].ContainsKey( $group ) ) {
        $queries[$language][$group] = @{}
    }
    if ( -Not $queries[$language][$group].ContainsKey( $query ) ) {
        $queries[$language][$group][$query] = @{}
    }
    if ( -Not $queries[$language][$group][$query].ContainsKey( $level ) ) {
        $queries[$language][$group][$query][$level] = $id
    }
}

function findMatchingName( $queries, $search ) {
    #Write-Host "Find matching name $search"
    foreach ( $cx1name in $queries.GetEnumerator() | Sort-Object Name ) {
        #Write-Host "`tcheck: $($cx1name.key)"
        if ( $cx1name.Key -ieq $search ) {
            #Write-Host "`t`tMatch"
            return $cx1name.Key
        } 
    }
    #Write-Host "No Match"

    return $null
}

function findMatchingQuery( $queries, $language, $group, $query, $level ) {
    #log "Checking SAST $($language) group $($group) query $($query)"
    $cx1lang = findMatchingName $queries $language
    if ( $null -ne $cx1lang ) {
        $cx1group = findMatchingName $queries[$cx1lang] $group
        if ( $null -ne $cx1group ) {
            $cx1query = findMatchingName $queries[$cx1lang][$cx1group] $query
            if ( $null -ne $cx1query ) {
                #log "`t`tSAST $($language) group $($group) query $($query) matches Cx1 $cx1lang group $cx1group query $cx1query"
                if ( $queries[$cx1lang][$cx1group][$cx1query].ContainsKey( $level ) ) {
                    return $queries[$cx1lang][$cx1group][$cx1query][$level]
                }
                
            } <#else {
                log "`t`tSAST $($language) group $($group) query $($query) has no matching query in Cx1 $cx1lang group $cx1group" $true
                return $null
            }#>
        } <#else {
            log "`tSAST $($language) group $($group) has no matching group in Cx1 $cx1lang" $true
            return $null
        }#>      
    } <#else {
        log "SAST language $($language) has no matching language in Cx1" $true
        return $null
    }#>
    return $null
}

function ToString( $query ) {
    return "$($query.Language) -> $($query.Group) -> $($query.Query) ($($query.Level))"
}
function ToCsv( $id, $query ) {
    return "$id;$($query.Level);$($query.Language);$($query.Group);$($query.Query);"
}

function findMapping( $mappings, $qid ) {
    foreach ( $mapping in $mappings ) {
        if ( $mapping.sastId -ieq $qid ) {
            return $mapping.astId
        }
    }
    return $null
}


###############
log "Starting query comparison between envs:"
log "`tSAST: $SASTUrl with user $SASTUser"
log "`tCx1: $Cx1Url tenant $Cx1Tenant with APIKey auth"
log ""

$outfile = "CxSAST-Cx1 comparison - preset $PresetName.csv"

if ( Test-Path $outfile ) {
    Write-Host "Output file $outfile already exists and will be overwritten"
    Remove-Item -Path $outfile
} else {
    Write-Host "Output will be written to $outfile"
}

log "Fetching SAST SOAP token"
$SASTSoapToken = getSASTToken $SASTUrl $SASTUser $SASTPassword $true
log "`tSOAP Token is: $(shorten $SASTSoapToken)"
$SASTRestToken = getSASTToken $SASTUrl $SASTUser $SASTPassword $false
log "`tREST Token is: $(shorten $SASTRestToken)"
log "Fetching Cx1 access token"
$Cx1Token = getCx1Token $IAMUrl $Cx1Tenant $Cx1APIKey
log "`tToken is: $(shorten $Cx1Token)"


log "Fetching SAST Presets"
$SASTPresets = getSASTPresets $SASTUrl $SASTRestToken "Failed to retrieve SAST Presets"
$SASTPresetID = 0

foreach ( $preset in $SASTPresets ) {
    if ( $preset.name -eq $PresetName ) {
        log "`tFound SAST preset $PresetName with ID $($preset.id)"
        $SASTPresetID = $preset.id
    }
}

if ( $SASTPresetID -eq 0 ) {
    log "Unable to find SAST preset $PresetName" $true
    return
}

$SASTPresetQueryIDs = (getSASTPresetDetails $SASTUrl $SASTRestToken $SASTPresetID "Failed to retrieve details for SAST preset $SASTPresetID").queryIds | Sort-Object | Get-Unique

$Cx1Presets = getCx1PresetByName $Cx1URL $Cx1Token $PresetName "Failed to retrieve Cx1 preset $PresetName"
$Cx1PresetID = 0

foreach ( $preset in $Cx1Presets.presets ) {
    if ( $preset.name -eq $PresetName ) {
        log "`tFound Cx1 preset $PresetName with ID $($preset.id)"
        $Cx1PresetID = $preset.id
    }
}

if ( $Cx1PresetID -eq 0 ) {
    log "Unable to find Cx1 preset $PresetName" $true
    return
} 

$Cx1PresetQueryIDs = (getCx1PresetDetails $Cx1URL $Cx1Token $Cx1PresetID "Failed to retrieve details for Cx1 preset $Cx1PresetID").queryIds | Sort-Object | Get-Unique

$SASTQueries = getSASTQueries $SASTUrl $SASTSoapToken "Failed to retrieve SAST Query Collection"
$AllSASTQueries = @{}
$SASTQueriesByID = @{}
$SASTQueries.CxWSQueryGroup | foreach-object {
    $language = $_.LanguageName
    $level = $_.PackageTypeName
    $group = $_.Name

    if ( $level -ieq "CX" -or $level -ieq "CORP" ) {        
        $_.Queries.CxWSQuery | foreach-object {
            addQuery $AllSASTQueries $level $language $group $_.name $_.QueryId
            $SASTQueriesByID["$($_.QueryId)"] = [pscustomobject]@{
                Language = $language
                Group = $group
                Query = $_.Name
                Level = $level
                AstID = -1
                Mapped = $false
                InPreset = $false
            }
        }
    }
}


log ""

$AllCx1Queries = @{}
$Cx1Queries = getCx1Queries $Cx1URL $Cx1Token "Failed to retrieve Cx1 Query Collection"
$Cx1QueriesByID = @{}
$Cx1Queries | foreach-object { 
    $language = $_.lang
    $level = $_.level
    $group = $_.group

    if ( $level -ieq "CORP" -or $level -ieq "CX" -or $level -ieq "TENANT" ) {
        addQuery $AllCx1Queries $level $language $group $_.name $_.Id
        $Cx1QueriesByID["$($_.Id)"] = [pscustomobject]@{
            Language = $language
            Group = $group
            Query = $_.name
            Level = $level
            SastID = -1
            Mapped = $false
            InPreset = $false
        }
    }
}

$QueryMappings = getCx1QueryMappings $Cx1URL $Cx1Token "Failed to retrieve Cx1 Query Mappings"

foreach ( $map in $QueryMappings.mappings ) {
    if ( $SASTQueriesByID.ContainsKey( $map.sastId ) ) {
        $SASTQueriesByID[ $map.sastId ].AstID = $map.astId
        $SASTQueriesByID[ $map.sastId ].Mapped = $true
    }
    if ( $Cx1QueriesByID.ContainsKey( $map.astId ) ) {
        $Cx1QueriesByID[ $map.astId ].SastID = $map.sastId
        $Cx1QueriesByID[ $map.astId ].Mapped = $true
    }
}

foreach ( $qid in $SASTPresetQueryIds ) {
    $SASTQueriesByID[ "$qid" ].InPreset = $true
    if ( $SASTQueriesByID[ "$qid" ].AstID -eq -1 ) {
        $astId = findMatchingQuery $AllCx1Queries $SASTQueriesByID[ "$qid" ].Language $SASTQueriesByID[ "$qid" ].Group $SASTQueriesByID[ "$qid" ].Query $SASTQueriesByID[ "$qid" ].Level
        if ( $null -ne $astId ) {
            $SASTQueriesByID[ "$qid" ].AstID = $astId
        }
    }
}

foreach ( $qid in $Cx1PresetQueryIds ) {
    $Cx1QueriesByID[ "$qid" ].InPreset = $true
    if ( $Cx1QueriesByID[ "$qid" ].SastID -eq -1 ) {
        $sastId = findMatchingQuery $AllSASTQueries $Cx1QueriesByID[ "$qid" ].Language $Cx1QueriesByID[ "$qid" ].Group $Cx1QueriesByID[ "$qid" ].Query $Cx1QueriesByID[ "$qid" ].Level
        if ( $null -ne $sastId ) {
            $Cx1QueriesByID[ "$qid" ].SastID = $sastId
        }
    }
}


"sep=;" | Out-File -FilePath $outfile
"In CxSAST Preset $PresetName;SAST QueryID;SAST Query Level;SAST Language;SAST Group;SAST Query;In Cx1 Preset $PresetName;CheckmarxOne QueryID;Cx1 Level;Cx1 Language;Cx1 Group;Cx1 Query;Is Mapped;Comment;" | Out-File -FilePath $outfile -Append
$count_mapped_in_both = 0
$count_match_in_both = 0
$count_missing_cx1 = 0
$count_deprecated_cx1 = 0

$output_cx1_queries = @()

foreach ( $qid in $SASTQueriesByID.GetEnumerator() | Sort-Object -Property {$_.Value.Level},{$_.Value.Language},{$_.Value.Group},{$_.Value.Query} ) {
    $q = $qid.Value

    if ( $q.InPreset ) {
        if ( $q.AstID -eq -1 -or -not $Cx1QueriesByID.ContainsKey( "$($q.AstID)" ) ) {
            # exists in SAST, but not in cx1
            $count_deprecated_cx1++
            "true;$(ToCsv $qid.Key $q)false;;;;;;;Deprecated in Cx1"| Out-File -FilePath $outfile -Append
        } else {
            # exists in both
            $astq = $Cx1QueriesByID[ "$($q.AstID)" ]
            if ( $astq.InPreset ) {
                if ( $q.Mapped ) {
                    $count_mapped_in_both++
                } else {
                    $count_match_in_both++
                }
                $output_cx1_queries += $q.AstID
            } else {
                $count_missing_cx1++
            }
            #in sast preset           
            "true;$(ToCsv $qid.Key $q)$($astq.InPreset);$(ToCsv $q.AstID $astq)$($q.Mapped);"| Out-File -FilePath $outfile -Append


        }

    }
}
log ""
log "There are $($SASTPresetQueryIds.count) queries in the SAST preset $PresetName"
log "There are $($Cx1PresetQueryIds.count) queries in the Cx1 preset $PresetName"
log ""
log " - There are $count_mapped_in_both queries in the SAST Preset $PresetName which have a mapped query that is in the Cx1 Preset $PresetName"
log " - There are $count_match_in_both queries in the SAST Preset $PresetName which have an un-mapped query but matching query (based on name) in the Cx1 Preset $PresetName"
log " - There are $count_missing_cx1 queries in the SAST Preset $PresetName which exist in Cx1, but are not in Cx1 Preset $PresetName" ($count_missing_cx1 -gt 0)
log " - There are $count_deprecated_cx1 queries in the SAST Preset $PresetName which have a mapping, but have been deprecated in Cx1" ($count_deprecated_cx1 -gt 0)
$count_missing_cxsast = 0

foreach ( $qid in $Cx1QueriesByID.GetEnumerator() | Sort-Object -Property {$_.Value.Level},{$_.Value.Language},{$_.Value.Group},{$_.Value.Query} ) {
    $q = $qid.Value
    if ( $q.InPreset -and -not $output_cx1_queries.Contains($qid.Key) ) {
        $count_missing_cxsast++
        if ( -not $SASTQueriesByID.ContainsKey( "$($q.SastID)" ) ) {
            #Write-Host "Cx1 Query $($qid.Key) ($(ToString $q))"
            "false;;;;;;true;$(ToCsv $qid.Key $q)false" | Out-File -FilePath $outfile -Append
        } else {
            $sastq = $SASTQueriesByID[ "$($q.SastID)" ]
            "false;$(ToCsv $q.SastID $sastq)true;$(ToCsv $qid.Key $q)false" | Out-File -FilePath $outfile -Append
        }
    }
}
log  " - There are $count_missing_cxsast queries in the CheckmarxOne Preset $PresetName which do not have a mapped or matching query in the SAST Preset $PresetName" ($count_missing_cxsast -gt 0)


log "Finished - review $outfile for details"
