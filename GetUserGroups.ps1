PARAM ($Principal = $env:username)
#************************************************
# GetUserGroups.ps1
# Version 1.0
# Date: 2/07/2014
# Author: Tim Springston
# Description: This script finds all groups a specific principal is a member of. It includes all groups scopes and SIDHistory memberships as well.
#************************************************
cls
$OutFile = $PWD.Path + "\" + $Principal + "GroupList.txt"
$ErrorActionPreference = "stop"
#Test user identity and if succesful get Identity object for this user from domain
try{
	$UserIdentity = New-Object System.Security.Principal.WindowsIdentity($Principal)
	$ForestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
	$DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
	}
catch [System.Exception]{Write-Host $_}
                 


$Groups = $UserIdentity.get_Groups()
$DomainSID = $UserIdentity.AccountDomainSid
$GroupCount = $Groups.Count

$AllGroupSIDHistories = @()
$SecurityGlobalScope  = 0
$SecurityDomainLocalScope = 0
$SecurityUniversalInternalScope = 0
$SecurityUniversalExternalScope = 0
$GroupSIDHistoryDetails = New-Object PSObject  
$GroupDetails = New-Object PSObject  

#Get user object SIDHistories
$DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$RootString = "LDAP://" + $DomainInfo.Name
$Root = New-Object  System.DirectoryServices.DirectoryEntry($RootString)
$searcher = New-Object DirectoryServices.DirectorySearcher($Root)
$searcher.Filter="(|(userprincipalname=$Principal)(name=$Principal))"
$results=$searcher.findone()
if ($results -ne $null){$SIDHistoryResults = $results.properties.sidhistory}
#Clean up the SIDs so they are formatted correctly
$SIDHistoryResults = @()
foreach ($SIDHistorySid in $SIDHistoryResults){
    $SIDString = (New-Object System.Security.Principal.SecurityIdentifier($SIDHistorySid,0)).Value
    $SIDHistoryResults  += $SIDString}

#Get user object SIDHistories
$SIDCounter = $SIDHistoryResults.count

#Resolve SIDHistories if possible to give more detail.
if (($Details -eq $true) -and ($SIDHistoryResults -ne $null))
    {
    $UserSIDHistoryDetails = New-Object PSObject
    foreach ($SIDHistory in $SIDHistoryResults)
          {
          $SIDHist = New-Object System.Security.Principal.SecurityIdentifier($SIDHistory)
          $SIDHistName = $SIDHist.Translate([System.Security.Principal.NTAccount])
          add-Member -InputObject $UserSIDHistoryDetails -MemberType NoteProperty -Name $SIDHistName  -Value $SIDHistory -force
          }
    }

foreach ($GroupSid in $Groups) 
    {     
    $Group = [adsi]"LDAP://<SID=$GroupSid>"
    $GroupType = $Group.groupType
               #Get group details
               if ($Group.name -ne $null)
                              {
                              #Get user object SIDHistories
        $DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $RootString = "LDAP://" + $DomainInfo.Name
        $Root = New-Object  System.DirectoryServices.DirectoryEntry($RootString)
        $searcher = New-Object DirectoryServices.DirectorySearcher($Root)
                   $searcher.Filter="(|(userprincipalname=$Group.name)(name=$Group.name))"
        $results=$searcher.findone()
        if ($results -ne $null){$SIDHistoryResults = $results.properties.sidhistory}
        #Clean up the SIDs so they are formatted correctly
        $SIDHistorySids = @()
        foreach ($SIDHistorySid in $SIDHistoryResults){
            $SIDString = (New-Object System.Security.Principal.SecurityIdentifier($SIDHistorySid,0)).Value
            $SIDHistorySids  += $SIDString}
                   If (($SIDHistorySids | Measure-Object).Count -gt 0) 
                                             {$AllGroupSIDHistories += $SIDHistorySids}
                                             $GroupName = $Group.name.ToString()
                 
                              #Resolve SIDHistories if possible to give more detail.
                              if ($SIDHistorySids -ne $null)
                       {

                       foreach ($GroupSIDHistory in $AllGroupSIDHistories)
                             {
                             $SIDHistGroup = New-Object System.Security.Principal.SecurityIdentifier($GroupSIDHistory)
                             $SIDHistGroupName = $SIDHistGroup.Translate([System.Security.Principal.NTAccount])
                             $GroupSIDHISTString = $GroupName + "--> " + $SIDHistGroupName
                             add-Member -InputObject $GroupSIDHistoryDetails -MemberType NoteProperty -Name $GroupSIDHistory  -Value $GroupSIDHISTString -force
                             }
                       }
                              }
                             
            #Count number of security groups in different scopes.
            switch -exact ($GroupType)
                  {"-2147483646"    {
                                    #Domain Global scope
                                    $SecurityGlobalScope++
                                    #Domain Global scope
                                    $GroupNameString = $GroupName + " (" + ($GroupSID.ToString()) + ")"
                                    add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name $GroupNameString  -Value "Domain Global Group"
                                    $GroupNameString = $null
                                    }
                  "-2147483644"     {
                                    #Domain Local scope
                                    $SecurityDomainLocalScope++
                                    $GroupNameString = $GroupName + " (" + ($GroupSID.ToString()) + ")"
                                    Add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name $GroupNameString  -Value "Domain Local Group"
                                     $GroupNameString = $null
                                    }
                                  
                  "-2147483640"   {
                                  #Universal scope; must separate local
                                  #domain universal groups from others.
                                  if ($GroupSid -match $DomainSID)
									    {
                                    	$SecurityUniversalInternalScope++
                                        $GroupNameString = $GroupName + " (" + ($GroupSID.ToString()) + ")"
                                        Add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name  $GroupNameString -Value "Local Universal Group"
                                        $GroupNameString = $null
                                        }                              
                                    else
                                        {
                                        $SecurityUniversalExternalScope++
										$GroupNameString =  $GroupName + " (" + ($GroupSID.ToString()) + ")"
                                        Add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name  $GroupNameString -Value "External Universal Group"
                                        $GroupNameString = $null
                                        }
                                  }
                  }

            }
                                             
Get-Date | Out-File -FilePath $OutFile -Encoding utf8
"Groups for user $Principal" | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
$UserID = $UserIdentity.Name.ToString()
"Domain\Name: $UserId" | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
$UserSID = $UserIdentity.User.ToString()
"User SID: $UserSID" | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
"Domain Name: $DomainName" | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
"Forest Name: $ForestName " | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
"***************" | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
$GroupDetails | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
"SIDHistory Group Details"  | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
"***************" | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
if ($GroupSIDHistoryDetails -ne $null)
	{$GroupSIDHistoryDetails | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append}
	else
		{"[NONE FOUND]" | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append}
"User SIDHistory Details"  | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
"***************" | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append
if ($UserSIDHistoryDetails -ne $null)
	{$UserSIDHistoryDetails | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append}
	else
		{"[NONE FOUND]" | Out-File -FilePath $OutFile -Encoding utf8 -Width 500 -append}

Write-Host "User group collection complete. Results are at $Outfile." -ForegroundColor Green
