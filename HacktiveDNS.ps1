#################################################################################
# HacktiveDNS.ps1 v1.0                                                          #
#                                                                               #
#  This script is intended to setup DNS Forward to other AD Servers             #
#                     WRITTEN BY: Dev Badlu aka badc0d3, OSCP                   #
#################################################################################
Param 
(
    [string]$RemoteADDomainName = 'da.vulndomain.corp',
    [string]$RemoteADIP = '192.168.20.3',
    [string]$RootDir = 'C:\TM\'
)


# CREATE FOLDER
New-Item -Type Directory -Path $RootDir -Force | Out-Null

# LOG FILE
$TimeVal = Get-Date -UFormat '%Y-%m-%d-%H-%M'
Start-Transcript "$RootDir\HackADTranscript-$TimeVal.txt" -Force

Add-DnsServerConditionalForwarderZone -Name $RemoteADDomainName -MasterServers $RemoteADIP -PassThru

Stop-Transcript