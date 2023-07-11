#################################################################################
# HacktiveTrust.ps1 v1.0                                                        #
#                                                                               #
#  This script is intended to setup a trust between this env and a remote ad    #
#                     WRITTEN BY: Dev Badlu aka badc0d3, OSCP                   #
#################################################################################
Param 
(
    [string]$RemoteADDomainName = 'da.vulndomain.corp',
    [string]$RemoteADIP = '192.168.20.3',
    [string]$RemoteADUser = 'dcadmin',
    [string]$RemoteADPassword = 'verySecure1',

    [ValidateSet('Bidirectional','Inbound','Outbound')]
    [string]$TrustType = 'Bidirectional',
    [string]$RootDir = 'C:\TM\'
)


# CREATE FOLDER
New-Item -Type Directory -Path $RootDir -Force | Out-Null

# LOG FILE
$TimeVal = Get-Date -UFormat '%Y-%m-%d-%H-%M'
Start-Transcript "$RootDir\HackADTranscript-$TimeVal.txt" -Force

$RemoteADContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $RemoteADDomainName, $RemoteADUser, $RemoteADPassword)
Add-DnsServerConditionalForwarderZone -Name $RemoteADDomainName -MasterServers $RemoteADIP -PassThru

try { 
    $RemoteADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($RemoteADContext) 
} catch { 
    Write-Warning "Error GetRemoteForest: $($($_.Exception).Message)" 
}

$CurrentADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

try { 
    $CurrentADForest.CreateTrustRelationship($RemoteADForest, $TrustType) 
    Write-Host "CreateTrustRelationship: Succeeded for domain $($RemoteADForest)" 
} catch { 
    Write-Warning "Error CreateTrustRelationship: Failed for domain$($RemoteADForest)`n`tError: $($($_.Exception).Message)" 
}

Stop-Transcript