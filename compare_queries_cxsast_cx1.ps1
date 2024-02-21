param (
    [Parameter(Mandatory = $true)][string]$SASTUrl,
    [Parameter(Mandatory = $true)][string]$SASTUser,
    [Parameter(Mandatory = $true)][string]$SASTPassword,
    [Parameter(Mandatory = $true)][string]$Cx1URL,
    [Parameter(Mandatory = $true)][string]$IAMUrl,
    [Parameter(Mandatory = $true)][string]$Cx1Tenant,
    [Parameter(Mandatory = $true)][string]$Cx1APIKey,
    [Parameter(Mandatory = $false)][bool]$CorpOnly = $true
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

function getCx1PresetQueries( $server, $token, $errormessage ) {
    $uri = "$($server)/api/presets/queries"
    return req $uri "GET" $token $errormessage
} 
function getCx1QueryMappings( $server, $token, $errormessage ) {
    $uri = "$($server)/api/queries/mappings"
    return req $uri "GET" $token $errormessage
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

function getCx1QueryDetails( $server, $token, $scope, $path, $errormessage ) {
    log "Get details for $scope $path"
    $safe_path = $path.Replace( "/", "%2f" )
    $uri = "$($server)/api/cx-audit/queries/$scope/$safe_path"
    return req $uri "GET" $token $errormessage
}

function getCx1Queries( $server, $token, $errormessage ) {
    $uri = "$($server)/api/cx-audit/queries"
    return req $uri "GET" $token $errormessage
}

function getSASTSoapToken($server, $user, $pass) {
    $body = @{
        username = $user
        password = $pass
        grant_type = "password"
        scope = "offline_access sast_api"
        client_id = "resource_owner_sast_client"
        client_secret = "014DF517-39D1-4453-B7B3-9930C563627C"
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
        throw "Could not authenticate - User: $user"
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

function addQuery( $queries, $level, $language, $group, $query ) {

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
        $queries[$language][$group][$query][$level] = @{
            "SAST_ID" = -1
            "Cx1_ID" = -1
            "Mapped_ID" = -1
        }
    }
}

function sevstr( $sev ) {
    if ( $sev -eq 0 ) {
        return "INFO"
    } elseif ( $sev -eq 1 ) {
        return "LOW"
    } elseif ( $sev -eq 2 ) {
        return "MEDIUM"
    } elseif ( $sev -eq 3 ) {
        return "HIGH"
    } elseif ( $sev -eq 4 ) {
        return "CRITICAL"
    } else {
        return "??"
    }
}

function addSASTQuery( $queries, $level, $language, $group, $query, $id ) {
    addQuery $queries $level $language $group $query    
    $queries[$language][$group][$query][$level]["SAST_ID"] = $id
}

function addCx1Query( $queries, $level, $language, $group, $query, $id ) {
    addQuery $queries $level $language $group $query
    # all overrides of the same query have the same Query ID in Cx1.
    foreach ( $level in $queries[$language][$group][$query].GetEnumerator() | Sort-Object Name ) {
        $level.Value["Cx1_ID"] = $id
    }
}

function hashstr( $str ) {
    if ( $str -eq "" ) { 
        return ""
    } else {
        $mystream = [IO.MemoryStream]::new([byte[]][char[]]$str)
        (Get-FileHash -InputStream $mystream -Algorithm SHA256).Hash
    }
}

function MakeRow( $SastQ, $Cx1Q ) {
    $row = [pscustomobject]@{
		Identical = $false
        Missing_Base_Query = $false
        Different_Base_Severity = $false
		Different_Query_Name = $false
        Missing_Corp_Override = $false
        Different_Corp_Severity = $false
        Different_Corp_Hash = $false

        SAST_QueryID = ""
        SAST_Language = ""
        SAST_Group = ""
        SAST_Query = ""
        SAST_Severity = ""
        SAST_CorpQueryID = ""
		SAST_CorpQueryName = ""
        SAST_CorpSeverity = ""
        SAST_CorpSourceHash = ""

        Cx1_QueryID = ""
        Cx1_Language = ""
        Cx1_Group = ""
        Cx1_Query = ""
        Cx1_Severity = ""
		Cx1_CorpQueryName = ""
        Cx1_CorpSeverity = ""
        Cx1_CorpSourceHash = ""
    }

    if ( $null -ne $SastQ ) {
        $row.SAST_QueryID = $SastQ.QueryID
        $row.SAST_Language = $SastQ.Language
        $row.SAST_Group = $SastQ.Group
        $row.SAST_Query = $SastQ.Query
        $row.SAST_Severity = $SastQ.Severity
        $row.SAST_CorpQueryID = $SastQ.CorpID
		$row.SAST_CorpQueryName = $SastQ.CorpName
        $row.SAST_CorpSeverity = $SastQ.CorpSeverity
        $row.SAST_CorpSourceHash = $SastQ.CorpSourceHash
    }

    if ( $null -ne $Cx1Q ) {
        $row.Cx1_QueryID = $Cx1Q.QueryID
        $row.Cx1_Language = $Cx1Q.Language
        $row.Cx1_Group = $Cx1Q.Group
        $row.Cx1_Query = $Cx1Q.Query
        $row.Cx1_Severity = $Cx1Q.Severity
		$row.Cx1_CorpQueryName = $Cx1Q.CorpName
        $row.Cx1_CorpSeverity = $Cx1Q.CorpSeverity
        $row.Cx1_CorpSourceHash = $Cx1Q.CorpSourceHash
    }

    if ( ($null -ne $SastQ -and $null -eq $Cx1Q) -or ($null -eq $SastQ -and $null -ne $Cx1Q) ) {
        $row.Missing_Base_Query = $true
    }
    if ( $null -ne $SastQ -and $null -ne $Cx1Q ) {
        if ( $SastQ.Severity -ne $Cx1Q.Severity ) {
            $row.Different_Base_Severity = $true
        }

        if ( ($SastQ.CorpSourceHash -ne "" -and $Cx1Q.CorpSourceHash -eq "") -or ($SastQ.CorpSourceHash -eq "" -and $Cx1Q.CorpSourceHash -ne "") ) {
            $row.Missing_Corp_Override = $true
        }

        if ( $SastQ.CorpSourceHash -ne $Cx1Q.CorpSourceHash ) {
            $row.Different_Corp_Hash = $true
        }

        $sast_final_sev = $row.SAST_Severity
        if ( $row.SAST_CorpSeverity -ne "" ) {
            $sast_final_sev = $row.SAST_CorpSeverity
        }
        $cx1_final_sev = $row.Cx1_Severity
        if ( $row.Cx1_CorpSeverity -ne "" ) {
            $cx1_final_sev = $row.Cx1_CorpSeverity
        }

        if ( $sast_final_sev -ne $cx1_final_sev ) {
            $row.Different_Corp_Severity = $true
        }
		
		if ( $SastQ.Query -ne $Cx1Q.Query -or ($SastQ.CorpName -ne "" -and $SastQ.CorpName -ne $SastQ.Query) -or ($Cx1Q.CorpName -ne "" -and $Cx1Q.CorpName -ne $Cx1Q.Query) ) {
			$row.Different_Query_Name = $true
		}
		
    }
	
	if ( $row.Missing_Base_Query -or $row.Missing_Corp_Override -or $row.Different_Base_Severity -or $row.Different_Corp_Hash -or $row.Different_Corp_Severity -or $row.Different_Query_Name ) {
		$row.Identical = $false
	} else {
		$row.Identical = $true
	}

    return $row

}

###############
log "Starting query comparison between envs:"
log "`tSAST: $SASTUrl with user $SASTUser"
log "`tCx1: $Cx1Url tenant $Cx1Tenant with APIKey auth"
log ""
if ( $CorpOnly ) {
    log "`t`$CorpOnly = true (will compare only corporate-level queries)"
} else {
    log "`t`$CorpOnly = false (will compare product-default- and corporate-level queries)"
}
log ""


$outfile = "CxSAST-Cx1 comparison - queries.csv"

log "Fetching SAST SOAP token"
$SASTSoapToken = getSASTSoapToken $SASTUrl $SASTUser $SASTPassword
log "`tToken is: $(shorten $SASTSoapToken)"
log "Fetching Cx1 access token"
$Cx1Token = getCx1Token $IAMUrl $Cx1Tenant $Cx1APIKey
log "`tToken is: $(shorten $Cx1Token)"

$QueryMappings = getCx1QueryMappings $Cx1URL $Cx1Token "Failed to retrieve Cx1 Query Mappings"
$QueryMappingsCount = $QueryMappings.mappings.length

$MappedIDs = @{}
foreach ( $map in $QueryMappings.mappings ) {
    $MappedIDs[$map.sastId] = $map.astId
}

$AllQueries = @{}

#$SASTQueries = $SASTQueriesMock #

<#
    Process:
        Go through Cx queries to generate product query map (Cx base query -> Cx1 base query [mapped])
        Go through Corp queries to add to base struct
        Go through Cx1 queries to check if they exist
#>

log ""
log "Fetching SAST queries"

$SASTQueries = getSASTQueries $SASTUrl $SASTSoapToken "Failed to retrieve SAST Query Collection"
$SASTQueriesByID = @{}

$SASTQueries.CxWSQueryGroup | foreach-object {
    $language = $_.LanguageName.ToUpper()
    $level = $_.PackageTypeName.ToUpper()
    $group = $_.Name.ToUpper()

    <#if ( $level -eq "TEAM" ) {
        $level = "TEAM_$($_.OwningTeam)"
    }#>

    if ( $level -eq "CX" ) {
        $_.Queries.CxWSQuery | foreach-object {
            $query = $_.Name.ToUpper()
            addSASTQuery $AllQueries $level $language $group $query $_.QueryId 

            $SASTQueriesByID["$($_.QueryId)"] = [pscustomobject]@{
                Language = $language
                Group = $group
                Query = $_.Name
                Product = $true
                QueryID = $_.QueryId
                AstID = -1
                Mapped = $false
				Matched = $False
                
                Severity = sevstr $_.Severity
                CorpID = ""
				CorpName = ""
                CorpSeverity = ""
                CorpSourceHash = ""
            }
            if ( $MappedIDs.ContainsKey( $_.QueryId ) ) {
                $SASTQueriesByID["$($_.QueryId)"].AstID = $MappedIDs["$($_.QueryId)"]
                $SASTQueriesByID["$($_.QueryId)"].Mapped = $true
            }
        }
    }
}

$SASTQueries.CxWSQueryGroup | foreach-object {
    $language = $_.LanguageName.ToUpper()
    $level = $_.PackageTypeName.ToUpper()
    $group = $_.Name.ToUpper()

    <#if ( $level -eq "TEAM" ) {
        $level = "TEAM_$($_.OwningTeam)"
    }#>

    if ( $level -eq "CORP" ) {
        $_.Queries.CxWSQuery | foreach-object {
            $query = $_.Name.ToUpper()
            addSASTQuery $AllQueries $level $language $group $query $_.QueryId 


            $baseQueryId = "$($_.QueryId)"
            if ( $AllQueries.ContainsKey($language) -and $AllQueries[$language].ContainsKey($group) -and $AllQueries[$language][$group].ContainsKey($query) -and $AllQueries[$language][$group][$query].ContainsKey("CX") ) {
                $baseQueryId = "$($AllQueries[$language][$group][$query]["CX"].SAST_ID)"
            }

            if ( -Not $SASTQueriesByID.ContainsKey( $baseQueryId ) ) {
                $SASTQueriesByID[$baseQueryId] = [pscustomobject]@{
                    Language = $language
                    Group = $group
                    Query = $_.Name
                    Product = $False
                    QueryID = $_.QueryId
                    AstID = -1
                    Mapped = $false
					Matched = $False

                    Severity = ""
                    CorpID = ""
					CorpName = ""
                    CorpSeverity = ""
                    CorpSourceHash = hashstr $_.Source
                }
            }

            
            $SASTQueriesByID[$baseQueryId].CorpID = $_.QueryId
            $SASTQueriesByID[$baseQueryId].CorpSeverity = sevstr $_.Severity
			$SASTQueriesByID[$baseQueryId].CorpName = $_.Name
            $SASTQueriesByID[$baseQueryId].CorpSourceHash = hashstr $_.Source
        }
    }
}


log ""
log "Fetching Cx1 queries - this may take a while"


#$Cx1Queries = $Cx1QueriesMock | Convertfrom-Json
$Cx1Queries = getCx1Queries $Cx1URL $Cx1Token "Failed to retrieve Cx1 Query Collection"
$Cx1PresetQueries = getCx1PresetQueries $Cx1URL $Cx1Token "Failed to retrieve Cx1 Preset Queries list"
$Cx1QueriesByID = @{}

$Cx1Queries | foreach-object { 
    $language = $_.lang.ToUpper()
    $level = $_.level.ToUpper()
    $group = $_.group.ToUpper()

    if ( $level -eq "CX" ) {
        $query = $_.Name.ToUpper()
		$astID = "$($_.Id)"
        addCx1Query $AllQueries $level $language $group $query $_.Id

        $Cx1QueriesByID[$astID] = [pscustomobject]@{
            Language = $language
            Group = $group
            Query = $_.Name
            Product = $True
            QueryID = $_.Id
            Path = $_.path
            Mapped = $False
			Matched = $False

            Severity = ""
            CorpSeverity = ""
			CorpName = ""
            CorpSourceHash = ""
        }

		if ( -not $_.isExecutable -and -not $CorpOnly ) {
			$q = getCx1QueryDetails $Cx1URL $Cx1Token "Cx" $Cx1QueriesByID["$($_.Id)"].Path "Failed to get details for Cx query $($Cx1QueriesByID[$astID].Path)"
			$Cx1QueriesByID[$astID].Severity = sevstr $q.Severity
		}
    }
}

log ""
log "Comparing queries"

foreach ( $Cx1PQ in $Cx1PresetQueries ) {
    if ( $Cx1QueriesByID.ContainsKey( "$($Cx1PQ.queryID)" ) ) {
        $Cx1QueriesByID[ "$($Cx1PQ.queryID)" ].Severity = $Cx1PQ.severity
    }
}

$Cx1Queries | foreach-object { 
    $language = $_.lang.ToUpper()
    $level = $_.level.ToUpper()
    $group = $_.group.ToUpper()

    if ( $level -eq "CORP" ) {
        $query = $_.Name.ToUpper()
        addCx1Query $AllQueries $level $language $group $query $_.Id

        if ( -Not $Cx1QueriesByID.ContainsKey( "$($_.Id)" ) ) {
            $Cx1QueriesByID["$($_.Id)"] = [pscustomobject]@{
                Language = $language
                Group = $group
                Query = $_.Name
                Product = $False
                QueryID = $_.Id
                Path = $_.path
                Mapped = $False
				Matched = $False
    
                Severity = ""
                CorpSeverity = ""
				CorpName = ""
                CorpSourceHash = ""
            }    
        }

        $q = getCx1QueryDetails $Cx1URL $Cx1Token "Corp" $Cx1QueriesByID["$($_.Id)"].Path "Failed to get details for CORP query $($Cx1QueriesByID["$($_.Id)"].Path)"
        $Cx1QueriesByID["$($_.Id)"].CorpSeverity = sevstr $q.Severity
        $Cx1QueriesByID["$($_.Id)"].CorpName = $_.Name
		$Cx1QueriesByID["$($_.Id)"].CorpSourceHash = hashstr $q.Source

        if ( $CorpOnly ) {
            try {
                $q = getCx1QueryDetails $Cx1URL $Cx1Token "Cx" $Cx1QueriesByID["$($_.Id)"].Path "Failed to get details for Cx query $($Cx1QueriesByID[$astID].Path)"
                $Cx1QueriesByID[$astID].Severity = sevstr $q.Severity
            } catch {

            }
        }
    }
}

log ""
log "Finding matches for queries that are not mapped"

foreach ( $language in $AllQueries.GetEnumerator() | Sort-Object Name ) {
    foreach ( $group in $language.Value.GetEnumerator() | Sort-Object Name ) {
        foreach ( $query in $group.Value.GetEnumerator() | Sort-Object Name ) {
			$sast_base_query = -1
			if ( $query.Value.ContainsKey("CX") ) { $sast_base_query = $query.Value["CX"]["SAST_ID"] }
			else { $sast_base_query = $query.Value["CORP"]["SAST_ID"] }
			
			$cx1_query = -1
			if ( $query.Value.ContainsKey("CX") ) { $cx1_query = $query.Value["CX"]["Cx1_ID"] }
			else { $cx1_query = $query.Value["CORP"]["Cx1_ID"] }
			
			if ( $sast_base_query -ne -1 -and $cx1_query -ne -1 ) {
				if ( -Not $SASTQueriesByID.ContainsKey( $sast_base_query ) ) {
					Write-Output "Somehow query ID $sast_base_query doesn't exist in the cache?"
				} else {
					if ( -Not $SASTQueriesByID["$sast_base_query"].Mapped ) {
						Write-Output "Query was not mapped, matching $sast_base_query with $cx1_query"
						$SASTQueriesByID["$sast_base_query"].Matched = $true
						$SASTQueriesByID["$sast_base_query"].AstID = $cx1_query
						$Cx1QueriesByID["$cx1_query"].Matched = $true
					}
				}
			}
		}
	}
}

log ""

# Some legacy queries will map to queries which no longer exist in Cx1 (deprecated)
$Cx1DeprecatedQuery = [pscustomobject]@{
    Language = "Deprecated"
    Group = "Deprecated"
    Query = "Deprecated"
    Product = $true
    QueryID = -1
    Path = "unknown"
    Mapped = $True
	Matched = $False

    Severity = ""
    CorpSeverity = ""
	CorpName = ""
    CorpSourceHash = ""
}    

$FinalMapping = @()
log "Generating output: $outfile"

foreach ( $row in $SASTQueriesByID.GetEnumerator() ) {
    if ( $row.Value.AstID -ne -1 ) {
        $astID = "$($row.Value.AstID)"

        if ( $Cx1QueriesByID.ContainsKey($astID) ) {
            if ( $row.Value.Mapped ) {
				$Cx1QueriesByID[$astID].Mapped = $true
			}
            $FinalMapping += MakeRow $row.Value $Cx1QueriesByID[$astID]
        } else {
            $Cx1DeprecatedQuery.QueryID = $astID
            $FinalMapping += MakeRow $row.Value $Cx1DeprecatedQuery
        }
    } else {
        $FinalMapping += MakeRow $row.Value $null
    }
}

foreach ( $row in $Cx1QueriesByID.GetEnumerator() ) {
    if ( -not $row.Value.Mapped -and -not $row.Value.Matched ) {
        $FinalMapping += MakeRow $null $row.Value
    }
}


$ctr = 0
foreach ( $row in $FinalMapping | Sort-Object SAST_QueryID ) {
    if ( ($row.Cx1_CorpSourceHash -ne "" -or $row.SAST_CorpSourceHash -ne "") -or -not $CorpOnly ) {
        if ( $ctr -eq 0 ) {
            Export-Csv -InputObject $row -Path $outfile
            $ctr = 1
        } else {
            Export-Csv -InputObject $row -Path $outfile -append
        }
    }

    if ( $row.SAST_CorpQueryID -ne "" -and -not $MappedIDs.ContainsKey( $row.SAST_CorpQueryID ) -and $row.Cx1_QueryID -ne "" ) {
        #Write-Output "Add corp to mapping: $($row.SAST_CorpQueryID) -> $($row.Cx1_QueryID)"
        $MappedIDs[$row.SAST_CorpQueryID] = $row.Cx1_QueryID
        if ( $row.SAST_QueryID -ne "" ) {
            $origin = "Product query #$($row.SAST_QueryID) $($row.SAST_Language) -> $($row.SAST_Group) -> $($row.SAST_Query) corp override"
        } else {
            $origin = "New custom corp query #$($row.SAST_CorpQueryID) $($row.SAST_Language) -> $($row.SAST_Group) -> $($row.SAST_Query)"
        }
        $QueryMappings.mappings += @{
            astID = $row.Cx1_QueryID
            sastID = $row.SAST_CorpQueryID
            origin = $origin
        }
    }
}

$blah = ($QueryMappings.mappings | Sort-Object -Property { [int] $_.sastID } )
$QueryMappings.mappings = $blah


$QueryMappings | ConvertTo-Json | Out-File "mappings.json"
if ( $QueryMappings.mappings.length -ne $QueryMappingsCount ) {
    Write-Output "Generated a mappings.json file with $($QueryMappings.mappings.length - $QueryMappingsCount) custom queries mapped"
} else {
    Write-Output "Saved the default query mapping provided by Cx1 to mappings.json"
}

log "Finished"

