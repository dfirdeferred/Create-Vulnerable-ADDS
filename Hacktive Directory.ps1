#################################################################################
# HacktiveDirectory.ps1 v1.1                                                    #
#                                                                               #
#  This script is intended to quickly install and configure ADDS and create an  #
#  Intentionally vulnerable domain                                              #
#                     WRITTEN BY: Darryl G. Baker, CISSP, CEH                   #
#                     UPDATED BY: Dev Badlu aka badc0d3, OSCP                   #
#################################################################################
Param 
(
    [string]$DefaultGateway = '192.168.20.1',
    [string]$IPAddress = '192.168.20.2',
    [string]$DomainName = 'ad.vulndomain.corp',
    [string]$DefaultPassword = 'verySecure1',
    [string]$RootDir = 'C:\TM\'
)

##############################################################
#                This Section Configures ADDS                #
##############################################################
#Configures Static IP and DNS if needed
function Conf-IP{
    Param (
        [string]$DefaultGateway,
        [string]$IPAddress
    )

    Write-Host "Setting up IP: $IPAddress, with a default gateway of $DefaultGateway" -Fore Cyan

    try {
        Remove-NetIPAddress -IPAddress $IPAddress -ErrorAction SilentlyContinue
        New-NetIPAddress -IPAddress $IPAddress -DefaultGateway $DefaultGateway -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ErrorAction SilentlyContinue    
    } catch {
        New-NetIPAddress -IPAddress $IPAddress -DefaultGateway $DefaultGateway -PrefixLength 24 -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ErrorAction SilentlyContinue    
    }

    Set-DNSClientServerAddress -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ServerAddresses $IPAddress
}

function Conf-ActiveDirectory{
    Param (
        [string]$DomainName
    )

    Write-Host 'Installing AD Domain Services and tools' -Fore Cyan
    Add-WindowsFeature AD-Domain-Services -IncludeManagementTools
    Install-ADDSForest -DomainName $DomainName -DomainNetBIOSName AD -InstallDNS
}

# Install ADDS and configure domain
function Conf-Domain{
    Param (
        [string]$DomainName,
        [int]$UserCount,
        [int]$ComputerCount,
        [string]$DefaultPassword
    )

    # Default Password
    $EncPwd = (ConvertTo-SecureString $DefaultPassword -AsPlainText -force)

    # Create Domain Admins
    Write-Host "`nCreating Domain Admins Accounts:" -Fore Cyan

    try {
        New-ADUser -GivenName dcadmin -Name dcadmin -Surname admin -UserPrincipalName "dcadmin@$DomainName" -SamAccountName dcadmin -AccountPassword $EncPwd -Enabled $True -ErrorAction Continue | Out-Null
        Write-Host "     dcadmin@$DomainName Created"
    }
    catch {
        Write-Host "     The user dcadmin already exists."
    }
    
    try {
        New-ADUser -GivenName sqladmin -Name sqladmin -Surname admin -UserPrincipalName "sqladmin@$DomainName" -SamAccountName sqladmin -AccountPassword $EncPwd -Enabled $True -ErrorAction Continue | Out-Null
        Write-Host "     sqladmin@$DomainName Created"
    }
    catch {
        Write-Host "     The user sqladmin already exists."
    }
    

    Write-Host '     Adding Accounts to Domain Admin Group'
    Add-ADGroupMember -Identity 'Domain Admins' -Members sqladmin,dcadmin | Out-Null

    $FirstNames =(
        "Aiden",
        "Jackson",
        "Mason",
        "Liam",
        "Jacob",
        "Jayden",
        "Ethan",
        "Noah",
        "Lucas",
        "Logan",
        "Caleb",
        "Caden",
        "Jack",
        "Ryan",
        "Connor",
        "Michael",
        "Elijah",
        "Brayden",
        "Benjamin",
        "Nicholas",
        "Alexander",
        "William",
        "Matthew",
        "James",
        "Landon",
        "Nathan",
        "Dylan",
        "Evan",
        "Luke",
        "Andrew",
        "Gabriel",
        "Gavin",
        "Joshua",
        "Owen",
        "Daniel",
        "Carter",
        "Tyler",
        "Cameron",
        "Christian",
        "Wyatt",
        "Henry",
        "Eli",
        "Joseph",
        "Max",
        "Isaac",
        "Samuel",
        "Anthony",
        "Grayson",
        "Zachary",
        "David"
    )

    $LastNames =(
        "Adams",
        "Alexander",
        "Allen",
        "Anderson",
        "Bailey",
        "Baker",
        "Barnes",
        "Bell",
        "Bennett",
        "Brooks",
        "Brown",
        "Bryant",
        "Butler",
        "Campbell",
        "Carter",
        "Clark",
        "Coleman",
        "Collins",
        "Cook",
        "Cooper",
        "Cox",
        "Davis",
        "Diaz",
        "Edwards",
        "Evans",
        "Flores",
        "Foster",
        "Garcia",
        "Gonzales",
        "Gonzalez",
        "Gray",
        "Green",
        "Griffin",
        "Hall",
        "Harris",
        "Hayes",
        "Henderson",
        "Hernandez",
        "Hill",
        "Howard"
    )

    # Create AD Users and Computers 
    Write-Host "`nCreating AD Users and Computers:" -Fore Cyan
    [int]$Count = 0
    While ($Count -lt $UserCount) {
        $UserFirstName = $FirstNames | Get-Random -Count 1
        $UserLastName = $LastNames | Get-Random -Count 1
        $DefaultUserID = "$UserFirstName.$UserLastName"
        $UPN = "$UserFirstName.$UserLastName@$DomainName"

        try {
            New-ADUser -Name $DefaultUserID -SamAccountName $DefaultUserID -GivenName $UserFirstName -Surname $UserLastName -UserPrincipalName $UPN -AccountPassword $EncPwd -Enabled $True -ErrorAction Continue
            $Count++
        }
        catch {
            Write-Host "     The user $DefaultUserID already exists."
        }
    }
    Write-Host "     Created $Count Users"

    1..$ComputerCount | %{
        try {
            New-ADComputer -Name COMP$_ -SamAccountName COMP$_ -Enabled $True | Out-Null
        }
        catch {
            Write-Host "     The Computer COMP$($_) already exists."
        }
    }
    Write-Host "     Created $ComputerCount Computers"

    # Create Generic GPO
    Write-Host "`nCreating Generic GPO:" -Fore Cyan
    $DN = 'DC=' + $DomainName.Replace('.',',DC=')
    New-GPO -Name 'GoodGPO' -ErrorAction SilentlyContinue | Out-Null
    New-GPLink -Name 'GoodGPO' -Target $DN -ErrorAction SilentlyContinue | Out-Null
    Write-Host "     Created GoodGPO GPO"
}

################################################################
#          This next section makes AD more vulnerable          #
################################################################

function Get-Users {
    Param (
        [int]$Count
    )
    
    return Get-ADUser -Filter { SamAccountName -ne "dcadmin" -AND SamAccountName -ne "sqladmin" -AND SamAccountName -ne "Guest" -AND SamAccountName -ne "krbtgt" -AND SamAccountName -ne "Administrator" } | Get-Random -Count $Count
}

# Add SPN to random user and to sqladmin
function Kerberoast-Prepare {
    Param (
        [int]$UserCount,
        [string]$DomainName
    )

    Write-Host "`nSetting up $UserCount accounts for Kerberoast:" -Fore Cyan
    $svc = -join((65..90) + (97..122) | Get-Random -Count 4 | %{[char]$_})

    # sqladmin User
    $sqlUser = Get-ADUser -Filter {SamAccountName -eq "sqladmin"}
    Set-ADUser -Identity $sqlUser -ServicePrincipalNames @{Add="$svc/SQL-01.$($DomainName):1433"} 
    Add-ADGroupMember -Identity "Domain Admins" -Members $sqlUser

    # Random User
    $rndUsers = Get-Users -Count $UserCount
    foreach ($rndUser in $rndUsers){
        $svc = -join((65..90) + (97..122) | Get-Random -Count 4 | %{[char]$_})
        Set-ADUser -Identity $rndUser -ServicePrincipalNames @{Add="$svc/SQL-01.$($DomainName):1433"} 
        Add-ADGroupMember -Identity "Domain Admins" -Members $rndUser
        Write-Host "     $($rndUser.SamAccountName)"
    }
}

# Disable Kerberos Preauth
function ASREPRoast-Prepare {
    Param (
        [int]$UserCount
    )

    Write-Host "`nDisable Kerberos Preauth for $UserCount accounts:" -Fore Cyan
    $rndUsers = Get-Users -Count $UserCount
    foreach ($rndUser in $rndUsers) {
        Set-ADAccountControl -Identity $rndUser -DoesNotRequirePreAuth 1
        Write-Host "     $($rndUser.SamAccountName)"
    }
}

# Changes kerb delegation on random computer             
function Delegate-Unconstrained {
    Param (
        [int]$UserCount
    )

    Write-Host "`nSetting up for $UserCount computers for Unconstrained Delegation:" -Fore Cyan
    $rndComputers = Get-ADComputer -Filter * | Get-Random -Count $UserCount
    foreach ($rndComputer in $rndComputers) {
        Set-ADAccountControl -Identity $rndComputer -TrustedForDelegation $true
        Write-Host "     $($rndComputer.SamAccountName)"
    }
}

# Give Standard user Full control of GPO
function Delegate-GPO {
    Param (
        [string]$GPOName,
        [int]$UserCount,
        [string]$DomainName
    )

    Write-Host "`nSetting up for $UserCount accounts for GPO Delegation:" -Fore Cyan
    $DN = 'DC=' + $DomainName.Replace('.',',DC=')

    New-GPO -Name $GPOName -ErrorAction SilentlyContinue | Out-Null
    New-GPLink -Name $GPOName -Target $DN -ErrorAction SilentlyContinue | Out-Null

    $rndUsers = Get-Users -Count $UserCount
    foreach ($rndUser in $rndUsers) {
        Set-GPPermission -Name $GPOName -TargetName $rndUser.SamAccountName -TargetType User -PermissionLevel GpoEditDeleteModifySecurity | Out-Null
        Write-Host "     $($rndUser.SamAccountName)"
    }
}

# Change Permissions to folder in SysVol
function Sysvol-Permissions {
    Param (
        [int]$UserCount,
        [string]$DomainName
    )

    Write-Host "`nSetting up for $UserCount accounts for Sysvol Permissions:" -Fore Cyan
    $zPath = "C:\Windows\SYSVOL\sysvol\$DomainName\Policies"
    $rndUsers = Get-Users -Count $UserCount
    $Acl = Get-Acl $zPath

    foreach ($rndUser in $rndUsers) {
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($rndUser.SamAccountName, "FullControl","Allow")
        $Acl.SetAccessRule($AccessRule)
        Write-Host "     $($rndUser.SamAccountName)"
    }

    Set-Acl $zPath $Acl
}

# Add user to Privileged group
function Elevate-User {
    Param (
        [int]$UserCount
    )

    Write-Host "`nSetting up for $UserCount accounts for Privileged Group:" -Fore Cyan
    $privGroups = ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Print Operators")

    foreach ($privGroup in $privGroups) {
        $rndUsers = Get-Users -Count $UserCount
        Write-Host "     $($privGroup)"
        foreach ($rndUser in $rndUsers) {
            Add-ADGroupMember -Identity $privGroup -Members $rndUser -ErrorAction Continue
            Write-Host "     - $($rndUser.SamAccountName)"
        }
    }
}

# Place password in description field
function Password-InDescription {
    Param (
        [int]$UserCount
    )

    Write-Host "`nSetting up for $UserCount accounts with Password in Description Field:" -Fore Cyan
    $rndUsers = Get-Users -Count $UserCount
    foreach ($rndUser in $rndUsers) {
        Set-ADUser $rndUser -Description "verySecure1"
        Write-Host "     $($rndUser.SamAccountName)"
    }
}

##############################################################
#                            Main                            #
##############################################################

# CREATE FOLDER
New-Item -Type Directory -Path $RootDir -Force | Out-Null

# LOG FILE
$TimeVal = Get-Date -UFormat '%Y-%m-%d-%H-%M'
Start-Transcript "$RootDir\HackADTranscript-$TimeVal.txt" -Force

$answer= Read-Host "Config AD Environment? y/n"
if ($answer.ToLower() -eq 'y') { 
    Conf-IP -DefaultGateway $DefaultGateway -IPAddress $IPAddress
    Conf-ActiveDirectory -DomainName $DomainName
    Write-Host "Please Reboot and then rerun the script with this option turn off."
} else {
    $answer= Read-Host "`nPopulate AD Environment? y/n"
    if ($answer.ToLower() -eq 'y') { 
        Conf-Domain -DomainName $DomainName -UserCount 50 -ComputerCount 50 -DefaultPassword $DefaultPassword
    }

    $answer= Read-Host "`nConfig AD Vulnerability? y/n"
    if ($answer.ToLower() -eq 'y') {
        Kerberoast-Prepare -UserCount 10 -DomainName $DomainName
        ASREPRoast-Prepare -UserCount 10
        Delegate-Unconstrained -UserCount 17
        Delegate-GPO -GPOName 'BadGPO' -UserCount 3 -DomainName $DomainName
        Sysvol-Permissions -UserCount 1 -DomainName $DomainName
        Elevate-User -UserCount 2
        Password-InDescription -UserCount 5
    }
}

Stop-Transcript
