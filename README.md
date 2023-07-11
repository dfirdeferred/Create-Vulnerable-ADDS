# VulnerableADDS-Services
Installs ADDS and configures a vulnerable domain on a windows server

This script is intended to run on a Windows Server in order to install Active Directory services and the vulnerable domain.

## Single Domain Setup

### Setup Active Directory
1. Open powershell as an admin
2. CD to the folder with the files
3. Run the HacktiveDirectory.ps1 file.  
    `./HacktiveDirectory.ps1 -DefaultGateway 192.168.20.1 -IPAddress 192.168.20.2`  
    Note: Replace the IP address with the actual IP you will like to use
4. You will see the following prompt, 'Config AD Environment'. Enter Y follow by the ENTER key.
5. You will also be prompted to create a break key password.
6. Once the setup is finish, reboot your machine.

### Populate Active Directory
1. Open powershell as an admin
2. CD to the folder with the files
3. Run the HacktiveDirectory.ps1 file.  
    `./HacktiveDirectory.ps1`
4. You will see the following prompt, 'Config AD Environment?'. Enter N follow by the ENTER key.
5. Next you will see the following prompt, 'Populate AD Environment?'. Enter Y follow by the ENTER key.
6. Next you will see a prompt asking if you will like to configure AD Vulnerabilities. If you would like to install vulnerabilities on your AD, then Enter Y otherwise Enter N.

### Summary
After running the scripts above you should have 2 Active Directory which the following setup:
1. Server: ad.vulndomain.com  
    IP Address: 192.168.20.2

## Trust Setup
You will need 2 windows servers instance running!

### Setup Active Directory
1. On the first server follow the setup above for single domain setup.
2. On the second server follow the setup above but add the following parameter DomainName in step 3.  
`./HacktiveDirectory.ps1 -DefaultGateway 192.168.20.1 -IPAddress 192.168.20.3 -DomainName da.vulndomain.com`
> Note: Installing the vulnerabilites is not needed for this.  

### Setup DNS on second server
1. Run the HacktiveDNS.ps1 script on the second server, replacing values as needed.  
`./HacktiveDirectory.ps1 -RemoteADDomainName ad.vulndomain.com -RemoteADIP 192.168.20.2`

### Setup Trust on first server
1. Run HacktiveTrust.ps1 on the first server, replacing values as needed.  
`./HacktiveTrust.ps1 -RemoteADDomainName da.vulndomain.com -RemoteADIP 192.168.20.3`

> Note: If you are using a VM template/clone please make sure you use the following command to generalize the server for info about sysprep visit microsoft [site].  
`%WINDIR%\system32\sysprep\sysprep.exe /generalize /shutdown /oobe`  

### Summary
After running the scripts above you should have 2 Active Directory which the following setup:
1. Server: ad.vulndomain.com  
    IP Address: 192.168.20.2  
    Trust: Bidirectional

1. Server: da.vulndomain.com  
    IP Address: 192.168.20.3  
    Trust: Bidirectional

## Domain Default Creds
Username: DCadmin  
Password: verySecure1

Username: sqladmin  
Password: verySecure1



[site]: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--generalize--a-windows-installation?view=windows-11