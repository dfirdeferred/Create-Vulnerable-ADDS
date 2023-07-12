# Create-Vulnerable-ADDS
This set of scripts is intended to run on Windows Servers. It can be used to install a vulnerable Active Directory Domain Services (AD DS) forest on one more computers and optionally create trusts between those forests.

**HacktiveDirectory.ps1:** This script is used to install a single-domain AD DS forest on a single server, populate the forest with objects, and create random vulnerabilities across the forest.
**HacktiveDNS.ps1:** This script configures DNS in preparation for creating a trust between two forests.
**HacktiveTrust.ps1:** This script configures a birectional trust between two forests.

## Single Forest Setup
Requirements: 1 computer (physical or virtual) running Server 2016 or newer.

### Deploy Active Directory
1. Clone or download this repository.
2. Open PowerShell as a Local Admin.
2. CD to the folder containing this repo's files.
3. Temporarily byoass the execution policy:  
    `Set-ExecutionPolicy Bypass -Scope Process -Force`
3. Run the HacktiveDirectory.ps1 script:   
    `./HacktiveDirectory.ps1 -DefaultGateway [YOUR GATEWAY] -IPAddress [DESIRED IP ADDRESS]`  
    Example:  
    `./HacktiveDirectory.ps1 -DefaultGateway 192.168.20.1 -IPAddress 192.168.20.2`  
4. You will see the following prompt:  
    `Config AD Environment? y/n`  
    Enter Y followed by the ENTER key.
5. You will also be prompted to create a password for the Directory Services Restore Mode (DSRM) account, also known as the "break-glass" account.
6. When the script finishes, restart your computer.

### Populate Active Directory
1. Open PowerShell as a Local Admin.
2. CD to the folder containing this repo's files.
3. Temporarily byoass the execution policy:  
    `Set-ExecutionPolicy Bypass -Scope Process -Force`
3. Run the HacktiveDirectory.ps1 file.  
    `./HacktiveDirectory.ps1`
4. You will see the following prompt  
    `Config AD Environment? y/n`  
    Enter N followed by the ENTER key.
5. Next you will see the following prompt,  
    `Populate AD Environment? y/n`  
    Enter Y follow by the ENTER key.
6. After AD is populated, you will be prompted to create vulnerabilities in the environment:  
`Config AD Vulnerability? y/n`   
    If you would like to install vulnerabilities in your AD, then Enter Y otherwise Enter N
7. Press the ENTER key.

### Summary
After running the scripts above you should have an AD DS forest with the following setup:
- Forest Name: ad.vulndomain.com  
- Domain Controller IP Address: 192.168.20.2
- Users:
    - Domain Admin u/p: DCadmin/verySecure1
    - SQL Admin u/p: sqladmin/verySecure1

## Two Forests and Trust Setup
Requirements: 2 computers (physical or virtual) running Server 2016 or newer.

### Deploy AD DS on Two Servers
1. On the first server, follow the steps above for "Single Forest Setup".
2. On the second server, follow the steps above for "Single Forest Setup", but specify a DomainName when first running HacktiveDirectory.ps1.  
    Example:  
    `./HacktiveDirectory.ps1 -DefaultGateway 192.168.20.1 -IPAddress 192.168.20.3 -DomainName da.vulndomain.com`

### Setup DNS on the Second Server
1. Run the HacktiveDNS.ps1 script on the second server.  
    Example:  
    `./HacktiveDNS.ps1 -RemoteADDomainName ad.vulndomain.com -RemoteADIP 192.168.20.2`

### Setup the Trust on First Server
1. Run HacktiveTrust.ps1 on the first server, replacing values as needed.  
    Example:
    `./HacktiveTrust.ps1 -RemoteADDomainName da.vulndomain.com -RemoteADIP 192.168.20.3`
> Note: If you are using a VM template/clone please make sure you use the following command to generalize the server. For more information about sysprep, visit [Microsoft](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--generalize--a-windows-installation?view=windows-11).  
`%WINDIR%\system32\sysprep\sysprep.exe /generalize /shutdown /oobe`  
For more information about sysprep visit microsoft [site].

### Summary
After running the scripts above you should have 2 AD DS forests with the following setups:
- Forest 1 Name: ad.vulndomain.com  
- Domain Controller 1 IP Address: 192.168.20.2
- Users:
    - Domain Admin u/p: DCadmin/verySecure1
    - SQL Admin u/p: sqladmin/verySecure1

- Forest 2 Name: da.vulndomain.com  
- Domain Controller 2 IP Address: 192.168.20.2
- Users:
    - Domain Admin u/p: DCadmin/verySecure1
    - SQL Admin u/p: sqladmin/verySecure1