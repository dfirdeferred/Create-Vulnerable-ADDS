#################################################################################
# HacktiveDirectory.ps1 v.1                                                     #
#                                                                               #
#  This script is intended to quickly install and configure ADDS and create an  #
#                         Intentionally vulnerable domain                       #
#                     WRITTEN BY: Darryl G. Baker, CISSP, CEH                   #
#                                                                               #
#################################################################################

Start-Transcript -Path C:\HackADTranscript.txt

##############################################################
#               This Section Configures ADDS                 #
#                                                            #
##############################################################




#Configures Static IP and DNS if needed
function Conf-IP{
New-NetIPAddress -IPAddress 192.168.20.2 -DefaultGateway 192.168.20.1 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex
Set-DNSClientServerAddress -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ServerAddresses 192.168.20.2
}



#Install ADDS and configure domain
function Conf-Domain{
    Add-WindowsFeature AD-Domain-Services -IncludeManagementTools
    Install-ADDSForest -DomainName ad.vulndomain.corp -DomainNetBIOSName AD -InstallDNS

    #Create AD Users and Computers 

    Import-Csv .\aduserlist.csv | %{
        New-ADUser -GivenName $_.GivenName -Name $_.Name -Surname $_.Surname -UserPrincipalName $_.UserPrincipleName -SamAccountName $_.SamAccountName -AccountPassword (ConvertTo-SecureString "verySecure1" -AsPlainText -force) -ErrorAction Continue
    }

    New-ADUser -GivenName admin -Name admin -Surname admin -UserPrincipalName dcadmin@ad.vulndomain.corp -SamAccountName dcadmin -AccountPassword (ConvertTo-SecureString "verySecure1" -AsPlainText -force) -ErrorAction Continue
    New-ADUser -GivenName admin -Name admin -Surname admin -UserPrincipalName sqladmin@ad.vulndomain.corp -SamAccountName sqladmin -AccountPassword (ConvertTo-SecureString "verySecure1" -AsPlainText -force) -ErrorAction Continue
    Get-Aduser -Filter * | Enable-ADAccount -ErrorAction Continue

    1..100 | %{
        New-ADComputer -Name COMP$_ -SamAccountName COMP$_  -Enabled $True
    }


    Write-Host "Letting AD catch up for 10 seconds"
    Start-Sleep -Seconds 10
    Write-Host "Ok, time to misconfigure some AD settings"
}



################################################################
#      This next section makes AD more vulnerable              #
#                                                              #
################################################################

#Changes kerb delegation on random computer             
function Delegate-Unconstrained{
    Get-ADComputer -Filter * | Get-Random -Count 17 | Set-ADAccountControl -TrustedForDelegation $true
    }

#add SPN to random user and to sqladmin
function Kerberoast-Prepare{
    $svc = -join((65..90) + (97..122) | Get-Random -Count 4 | %{[char]$_})
    $aduser = Get-ADUser -Filter {sAMAccountName -ne "dcadmin"} | Get-Random -Count 1 | select samaccountname 
    Set-ADUser -Identity $aduser -ServicePrincipalNames @{Add="$svc/SQL-01.ad.vulndomain.corp:1433"} 
    Add-ADGroupMember -Identity "Domain Admins" -Members $aduser

    Set-ADUser -Identity sqladmin -ServicePrincipalNames @{Add="$svc/SQL-01.ad.vulndomain.corp:1433"} 
    Add-ADGroupMember -Identity "Domain Admins" -Members $sqladmin
    }


#Give Standard user Full control of GPO
function Delegate-GPO{
    new-gpo -name TestGPO -ErrorAction SilentlyContinue
    New-GPLink -Name "TestGPO" -Target dc=ad,dc=vulnhub,dc=corp -ErrorAction SilentlyContinue 
    $user = Get-ADUser -Filter * | Get-Random -Count 3 | select samaccountname
    Set-GPPermission -Name TestGPO -TargetName $user.samaccountname -TargetType User -PermissionLevel GpoEditDeleteModifySecurity 
    }


#Change Permissions to folder in SysVol
function Break-SysvolPermissions{
    $zpath = "C:\SYSVOL\sysvol\ad.vulndomain.corp\Policies"
    $zuser =  Get-ADUser -Filter {sAMAccountName -ne "dcadmin"} | Get-Random -Count 1 | select samaccountname
    $Acl = Get-Acl $zpath
    $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule($zuser.samaccountname, "FullControl","Allow")
    $Acl.SetAccessRule($Ar)
    Set-Acl $zpath $Acl
    }

#Disable Kerberos Preauth
function ASREPRoast-Prepare{
        $asrepuser = Get-ADUser -Filter {sAMAccountName -ne "dcadmin"} | Get-Random -Count 10 | select samaccountname
        Set-ADAccountControl -Identity $asrepuser.samaccountname -DoesNotRequirePreAuth 1
        }

#Add user to Privileged group
function Elevate-User{
    1..5 | %{
        $privgroups = ("Domain Admins","Enterprise Admins","Schema Admins","Administrators", "Print Operators")
        $eluser = Get-ADUser -Filter {sAMAccountName -ne "dcadmin"} | Get-Random -Count 1 | select samaccountname
        $elgroup = $privgroups | Get-Random -Count 1
        Add-ADGroupMember -Identity $elgroup -Members $eluser
        }
    }

#Place password in description  field
function Password-InDescription{
    1..5 | %{
        $randomuser = Get-ADUser -Filter {sAMAccountName -ne "dcadmin"} | Get-Random -Count 1 | select samaccountname
        Set-ADUser $randomuser.samaccountname -Description "verySecure1"
    }
}



########################################################
#                                                      #
#               Main                                   #
#                                                      #
########################################################



#Sets static IP based on user's response
$answer= Read-Host "DC's require a static IP address. Would you like the script to change your static IP to '192.168.20.2' for you? Y/n"
if($answer -eq 'Y' -or 'y'){ 
    Conf-IP
    Conf-Domain
    Delegate-Unconstrained
    Kerberoast-Prepare
    Delegate-GPO
    Break-SysvolPermissions
    ASREPRoast-Prepare
    Elevate-User
    Password-InDescription
    }
else
    {
    Conf-Domain
    Delegate-Unconstrained
    Kerberoast-Prepare
    Delegate-GPO
    Break-SysvolPermissions
    ASREPRoast-Prepare
    Elevate-User
    Password-InDescription
    }

Stop-Transcript

