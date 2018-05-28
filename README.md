# EVaultUtils
This is a personal list of scripts I use in test environment only. Free free to use them as-is, I know I do.

# How-To use "Portal Forensics Collector" PFC.ps1?

PFC.ps1 is a PowerShell script that collects system information, exe.config files, web.config files, log files, hosts file, and DBs used with PORTAL.

It has been designed to work on single server install of PORTAL but can be used for distributed installation, it will just skip the components it does not find on that server.


The script is asking if the Data Bases should be collected = it gives the option to do not collect them.

If you choose to collect the DBs it will get the following DBs :

     EVaultWeb

     SiteManagement

     UserManagement

     WebCC

     VaultReporting



Note : this script collects DBs from SQL server or SQL Express.



This script reads only and stores the collected information into an encrypted zip file on c:\ with the following format :

   C:\evaultsupport-ticket number-hostname-DATE-TIME.zip

   This Zip file contains a file PFC.txt which contains system info collected and original location of config and log files collected



How to use the script :

1. Copy the script and other files in PFC zip (pswd: EVault) on c:\ (or to a location of your choice) on the PORTAL server

2. Open a PowerShell CLI using the "Run as administrator" option

3. Type (for first time use on this server):
Set-ExecutionPolicy -ExecutionPolicy Unrestricted

4. Select Y (Yes)

5. In this PowerShell session go to c:\ (or to the location you placed the script in, together with 7za.exe) and type .\PFC.ps1  to trigger the script execution

6. Answer Y when asked for Data Base collect if the SQL server is on this PORTAL server

7. After the script execution send us the ZIP file produced




PFC Current version is : 1.8 You can download the latest version from:

https://github.com/CailleauThierry/EVaultUtils > updated versions will be posted here when available