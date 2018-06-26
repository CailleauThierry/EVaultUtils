####################################################################################################
#          PORTAL Forensics Collector : V1.9
#
#          EVault
#
#
# gets system information  + install/upgrade logs + *.exe.config files
# + web.config files and log files and their respective path
# + host file + system & application Windows event logs (first 100 warnings and errors)
# + Portal DBs if requested
#
# Result stored in an encrypted zip file on c:\ with the following format :
#  C:\evaultsupport-ticketnumber-hostname-DATE-TIME.zip
#
# Script can be executed from any mapped drive's folder in a PowerShell session ran as Administrator
# with Set-ExcecutionPolicy RemoteSigned
#
# Script is composed of the following files (all should be copied to C:\):
#   PFC.ps1      # this script file
#   7za.exe               # 7-zip CLI version under GNU LGPL license
#   license.txt           # 7-Zip GNU LGPL license for use and distribution
#   readme.txt            # 7-Zip Command line version readme
#   7-zip.chm             # 7-Zip Compiled HTML help
#
####################################################################################################

<#  --------------  Changes History  -----------------
Version 1.9.0.1:
- Introducing new versioning as 2.0 could mean something else for PFC in the future
- Now collecting log files from C:\Program Files\Carbonite Server Backup\

Version 1.9:
- Now changed "renamed as: Web.config_ParentFolder_Web.config" to identify "Web.config" files easier also when sorting them by name or by extension. Example "Web.config_Status_Web.config" from the C:\inetpub\Portal Legacy\Status\Web.config

Version 1.8 ongoing:
- Consolidated ununsed return value consuming variables. Linter says "The variable 'ConsumeReturnValue' is assigned but never used. (PSUseDeclaredVarsMoreThanAssignments)" which is expected (already added at end of version 1.7 but not worth changing version number for that)
- Adding $env:tmp\Setup.log and $env:tmp\Installer-ConfigFileManager.log to Catpure install log available

Version 1.7:
- Fixes an issue in the regex filter to indentify the SQL Instance name in order to allow SQL backup, Also on SQL 2008 R2
- Tested on Portal 8.25 on Windows 2012 R2 Standard running Microsoft SQL Server 2008 R2 (SP2) - 10.50.4000.0 (X64)

Version 1.6:
- Collects Portal's SQL databases also with a SQL Named Instance
- Collects msinfo32.nfo
- Collects most recent SQL ERRORLOG
 Known issues in v 1.6:
  - scripts can end up deleting collection folder even if .zip file was not generated
  - sometime the SQL databases are not backed up (SQL 2008 R2)
  - script is sometimes slow at collecting all the forensics (performance issue)

Version 1.5:
- mostly version number management

Version 1.4:
- fixing SQL backup when registry path changed to standard one because of a named instance

Version 1.3:
- changed the branding within the script
- made the script to run from anywhere

Version 1.2 :
- changed the collect folder name to include Ticket number and hostname before the date and time
- changed the Windows event log export to file to create one file per catalogue including both warnings and errors (instead of separated files)
- added the execution path in PFC.txt in order to know from where was executed the script
- changed the osql to make it PowerShell v2 compliant
- added the zip function : now all files are stored into an encrypted zip file (and the files collected and folder are deleted after the zip file creation)

Version 1.1 :
- moved PFC.txt from C: to collect folder created by the script
- added the statement about PowerShell v3 (and above) limitation. A later version may come with PowerShell v2 (and above) support
- modified the output '=== No Data Base collected according to user choice ===' to make it more visible


--------------  end of Changes History  -----------------
#>

<#
	.SYNOPSIS
		PFC is a PowerShell script that collects system information, exe.config files, web.config files, log files, hosts file, and DBs used with PORTAL application from Seagate CSES (Evault)

	.DESCRIPTION
		PFC : PORTAL Forensics Collector : V1.2 is a Seagate CSES tool used to collect configuration and sys infos from a PORTAL application server.
		It has been designed to work on single server install of PORTAL but can be used for distributed installations (you can look at the script to see where it's looking for file and see if you need to modify it to match the distributed installation specifics)
		Script is asking if the Data Bases should be collected = it gives the option to do not collect them.

	.PARAMETER
		no parameter

	.EXAMPLE.
		Launch the script by typing .\PFC.ps1 in a PowerShell CLI

	.INPUTS
		no input

	.OUTPUTS
		creates an encrypted zip file C:\evaultsupport-ticket number-hostname-DATE-TIME  with DATE-TIME = current date and time, and place all files collected into it
		zip file contains a file PFC.txt which lists system info collected and original location of config and log files collected

	.NOTES
		Script must be executed from C:\ in a PowerShell session ran as Administrator

	.LINK
		support@evault.com

	.LINK
		www.seagate.com

#>

# This script requires PowerShell version 2 or above to run
#Requires -Version 2.0



# function putting all the files into an encrypted zip file
function Set-7zaPswd{
	begin {
	$password = Read-Host -assecurestring "Please enter the zip's password"
	}
	process {
	# runs once per pipeline object
    # switching to C:\ to avoid creating a zip in the directory we zip
	$currentdir = Get-Location
	Push-Location
	$zipdir = Split-Path -Path $currentdir -Parent
	Set-Location $zipdir

	# here $_ represents the files to compress
	if (-not (test-path ./7za.exe)) {throw "./7za.exe needed in one directory higher than your current location"}
	# this is a powershell invokation of the 7z.exe
	$pswd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
	# $_.DirectoryName.Split('\\')[-1] + ".zip" just take the last entry of the directory name an use this as the .zip filename
	$ConsumeReturnValue = & ./7za.exe a -mmt=off  ($_.DirectoryName.Split('\\')[-1] + ".zip") ("-p$pswd") $_.FullName
	#The Remove-Variable cmdlet takes the name of the variable as a parameter, not the $variable itself
	Remove-Variable pswd
    Pop-Location
	}
	end {
	$reslutingzip = ($_.DirectoryName.Split('\\')[-1] + ".zip")
	return ($reslutingzip)
	}
}

function Get-SQLBackupDirectoryForInstance
{
	[CmdletBinding()]
	param (
		[Parameter(Position = 0, Mandatory = $true)]
		[System.String]$InstanceName,
		[Parameter(Position = 1)]
		[System.String]$Host_Name = 'YourHostName'
	)

	process
	{
		try
		{
			[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null
			if ($Host_Name = 'YourHostName')
			{
				$Host_Name = $env:computername
				Write-Verbose "The script took the local hostname from `$env:computername"
			}
			$sqlserver = $Host_Name + "\" + $InstanceName
			#create a new server object
			$server = New-Object ("Microsoft.SqlServer.Management.Smo.Server") "$sqlserver"
			#display default backup directory for debugging
			return $server.Settings.BackupDirectory
		}
		catch
		{
			Write-Verbose "SQL Object Creation did not work"
		}
	}
}

function Get-SQLErrorLogPathForInstance
{
	[CmdletBinding()]
	param (
		[Parameter(Position = 0, Mandatory = $true)]
		[System.String]$InstanceName,
		[Parameter(Position = 1)]
		[System.String]$Host_Name = 'YourHostName'
	)

	process
	{
		try
		{
			[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null
			if ($Host_Name = 'YourHostName')
			{
				$Host_Name = $env:computername
				Write-Verbose "The script took the local hostname from `$env:computername"
			}
			$sqlserver = $Host_Name + "\" + $InstanceName
			#create a new server object
			$server = New-Object ("Microsoft.SqlServer.Management.Smo.Server") "$sqlserver"
			#display default backup directory for debugging
			return $server.ErrorLogPath
		}
		catch
		{
			Write-Verbose "SQL Object Creation did not work"
		}
	}
}

$ConsumeReturnValue = Get-ChildItem
$ErrorActionPreference = "SilentlyContinue"

# save the execution path
Push-Location
$execpath = Get-Location  # saved in a variable as well to print it into the PFC.txt

# ask user for DB collect or not
Write-Output "------------------------------------- PORTAL Forensics Collector -------------------------------------"
Write-Output " result stored in a zip file C:\evaultsupport-ticket number-hostname-DATE-TIME.zip"
Write-Output "------------------------------------------------------------------------------------------------------"
Write-Output "Do you want to collect Portal Data Bases ? y or n"
$DBcollect = Read-Host "y/n"

# ask user for the ticket number
$nbchar = 42000
While (($nbchar -gt 42) -or (!$nbchar))
{
	Write-Output " "
	Write-Output "Please enter your ticket number ?"
	Write-output "If you do not know your ticket number you can enter any other informative string. Limitations are : `r`n 1. Use only numbers or letters `r`n 2. Do not enter more than 42 characters`r`n"
	$ticketnb = Read-Host "Ticket#"
	$nbchar = $ticketnb.length
	If (!$nbchar) {Write-Output "!!! you can't leave this empty"}
	If ($nbchar -gt 42) {Write-Output "!!! you can't enter more than 42 characters here (this script is H2G2 compliant ;)"}
}

# get the hostname
$serverhostname = hostname

# create destination folder  c:\evaultsupport-ticket number-hostname-DATE-TIME
Set-Location $execpath
$Now = get-date -uformat "%Y-%m-%d-%A-%kH%M"
$MyPath_org = 'evaultsupport-' + $ticketnb + '-' + $serverhostname + '-' + $Now
$ConsumeReturnValue = new-item -itemtype directory $MyPath_org
$MyPath = "$execpath" + '\' + "$MyPath_org"
Set-Location $MyPath

date >> PFC.txt   # date the files have been collected + contains the path to files collected
Write-Output "PORTAL Forensics Collector : V1.6" >> PFC.txt
Write-Output "Script execution path =" $execpath.Path >> PFC.txt # write the execution path

msinfo32.exe /nfo $MyPath\msinfo32.nfo

# collect system info
Write-Output "---SYSTEM INFOS---" >> PFC.txt
Get-WmiObject win32_computersystem | Format-List * >> PFC.txt
Write-Output "---SERVICES STATUS---" >> PFC.txt
Get-Service | Sort-Object displayname >> PFC.txt

# collect Windows logs errors and warnings and create csv files (using , delimiter and " text separator )
# ---SYSTEM LOG 100 LAST ERRORS AND WARNINGS---
Get-EventLog system -new 100 -entrytype Error,warning | Select-Object * | Export-Csv ($MyPath + "\system100errors-warnings.csv") -NoTypeInformation
# ---APPLICATION LOG 100 LAST ERRORS AND WARNINGS---
Get-EventLog application -new 100 -entrytype Error,warning | Select-Object * | Export-Csv ($MyPath + "\application100errors-warnings.csv") -NoTypeInformation

Write-Output "---INSTALLED APPLICATIONS---" >> PFC.txt
(Get-WmiObject Win32_Product | Sort-Object Vendor, Name | Format-Table Vendor, Name, Version -groupBy Vendor) >> PFC.txt

if ( $PSVersionTable.PSVersion.Major -ge 4)
{
	Write-Output "---WINDOWS ROLES AND FEATURES---" >> PFC.txt
	Get-WindowsFeature | Where-Object installed >> PFC.txt
}
else
{
	Write-Output "---PowerShell Version installed on this machine does not have Get-WindowsFeature command---" >> PFC.txt
	Write-Output " Warning : PowerShell Version on this machine does not have Get-WindowsFeature command, Windows Roles and Features should be collected manually."
}

Write-Output "---POWERSHELL DRIVES---" >> PFC.txt
Get-PSDrive >> PFC.txt

Write-Output "---IP SETTINGS---" >> PFC.txt
ipconfig /all | findstr IP >> PFC.txt

# collect infos on listening ports and established connections
Write-Output "---LISTENING PORTS AND ESTABLISHED CONNECTIONS---" >> PFC.txt
netstat -ano >> PFC.txt

# collect the hosts file
Copy-Item C:\Windows\System32\drivers\etc\hosts $MyPath

# collect web.config files
$MyPath2 = 'C:\inetpub'

Set-Location $MyPath2
if ( (Get-Location).Path -eq $MyPath2 )
{
if ( $res = Get-ChildItem . -Include web.config -Recurse -Force )
{
    Set-Location 'C:\'   # this looks redundant but might be a workaround
	Set-Location $MyPath
	Write-Output "WEB.CONFIG FILES FOUND:" >> PFC.txt
	for ($i = 0 ; $i -ne $res.Length ; $i++)
	{
		Write-Output (($res[$i] -as [string]) + "          renamed as: " + "Web.config_" + ($res[$i].DirectoryName.Split('\')[-1]) + "_Web.config") >> PFC.txt
		$param = ($MyPath + "\") + "Web.config_" + ($res[$i].DirectoryName.Split('\')[-1]) + "_Web.config"
		Copy-Item ($res[$i] -as [string]) $param
	}
}
}
else
{
	Set-Location $MyPath
	Write-Output "FOLDER NOT FOUND : C:\inetpub\" >> PFC.txt
}



# collect Portal log files
# first in C:\logs
# then in C:\Program Files\Carbonite Server Backup\
# then in legacy C:\Program Files\EVault Software
# then in legacy C:\Program Files (x86)\EVault Software

$MyPath2 = 'C:\logs'
Set-Location $MyPath2
if ( (Get-Location).Path -eq $MyPath2 )
{
	if ( $res = Get-ChildItem . -Include *.log -Recurse -Force )
	{
    	Set-Location 'C:\'
		Set-Location $MyPath
		Write-Output "LOG FILES FOUND in c:\logs\ :" >> PFC.txt
		for ($i = 0 ; $i -ne $res.Length ; $i++)
		{
			Write-Output ($res[$i] -as [string]) >> PFC.txt
			Copy-Item ($res[$i] -as [string]) $MyPath
		}
	}
}
else
{
	Set-Location $MyPath
	Write-Output "FOLDER NOT FOUND : C:\logs\" >> PFC.txt
}

$MyPath2 = 'C:\Program Files\Carbonite Server Backup\'
Set-Location $MyPath2
if ( (Get-Location).Path -eq $MyPath2)
{
	if ( $res = Get-ChildItem . -Include *.log -Recurse -Force )
	{
    	Set-Location 'C:\'
		Set-Location $MyPath
		Write-Output "LOG FILES FOUND in C:\Program Files\Carbonite Server Backup\" >> PFC.txt
		for ($i = 0 ; $i -ne $res.Length ; $i++)
		{
			Write-Output ($res[$i] -as [string]) >> PFC.txt
			Copy-Item ($res[$i] -as [string]) $MyPath
		}
	}
	else
	{
		Set-Location $MyPath
		Write-Output "LOG FILES NOT FOUND : C:\Program Files\Carbonite Server Backup\" >> PFC.txt
	}
}
else
{
	Set-Location $MyPath
	Write-Output "FOLDER NOT FOUND : C:\Program Files\Carbonite Server Backup\" >> PFC.txt
}

$MyPath2 = 'C:\Program Files\EVault Software'
Set-Location $MyPath2
if ( (Get-Location).Path -eq $MyPath2)
{
	if ( $res = Get-ChildItem . -Include *.log -Recurse -Force )
	{
    	Set-Location 'C:\'
		Set-Location $MyPath
		Write-Output "LOG FILES FOUND legacy C:\Program Files\EVault Software\" >> PFC.txt
		for ($i = 0 ; $i -ne $res.Length ; $i++)
		{
			Write-Output ($res[$i] -as [string]) >> PFC.txt
			Copy-Item ($res[$i] -as [string]) $MyPath
		}
	}
	else
	{
		Set-Location $MyPath
		Write-Output "LOG FILES NOT FOUND : legacy C:\Program Files\EVault Software\ " >> PFC.txt
	}
}
else
{
	Set-Location $MyPath
	Write-Output "FOLDER NOT FOUND : legacy C:\Program Files\EVault Software\" >> PFC.txt
}


$MyPath2 = 'C:\Program Files (x86)\EVault Software'
Set-Location $MyPath2
if ( (Get-Location).Path -eq $MyPath2 )
{
	if ( $res = Get-ChildItem . -Include *.log -Recurse -Force )
	{
		Set-Location $MyPath
		Write-Output "LOG FILES FOUND in legacy C:\Program Files (x86)\EVault Software\:" >> PFC.txt
		for ($i = 0 ; $i -ne $res.Length ; $i++)
		{
			Write-Output ($res[$i] -as [string]) >> PFC.txt
			Copy-Item ($res[$i] -as [string]) $MyPath
		}
	}
	else
	{
		Set-Location $MyPath
		Write-Output "LOG FILES NOT FOUND : legacy C:\Program Files (x86)\EVault Software\ Could be a newer Carbonite Portal with no depenencies on 32-bit Programs" >> PFC.txt
	}
}
else
{
	Set-Location $MyPath
	Write-Output "FOLDER NOT FOUND : legacy C:\Program Files (x86)\EVault Software\" >> PFC.txt
}

# collect inetpub log files
$MyPath2 = 'C:\inetpub'
Set-Location $MyPath2
if ( (Get-Location).Path -eq $MyPath2 )
{
	if ( $res = Get-ChildItem . -Include *.log -Recurse -Force )
	{
    	Set-Location 'C:\'
		Set-Location $MyPath
		Write-Output "INETPUB LOG FILES FOUND:" >> PFC.txt
		for ($i = 0 ; $i -ne $res.Length ; $i++)
		{
			Write-Output ($res[$i] -as [string]) >> PFC.txt
			Copy-Item ($res[$i] -as [string]) $MyPath
		}
	}
}
else
{
	Set-Location $MyPath
	Write-Output "FOLDER NOT FOUND : C:\inetpub\" >> PFC.txt
}


# collect *.exe.config files
$MyPath2 = 'C:\Program Files'
Set-Location $MyPath2
if ( (Get-Location).Path -eq $MyPath2 )
{
	if ( $res = Get-ChildItem . -Include *.exe.config -Recurse -Force )
	{
		Set-Location $MyPath
		Write-Output ".EXE.CONFIG FILES FOUND:" >> PFC.txt
		for ($i = 0 ; $i -ne $res.Length ; $i++)
		{
			Write-Output ($res[$i] -as [string]) >> PFC.txt
			Copy-Item ($res[$i] -as [string]) $MyPath
		}
	}
}
else
{
	Set-Location $MyPath
	Write-Output "FOLDER NOT FOUND : C:\Program Files\" >> PFC.txt
}

# collects install logs files: $env:tmp\Setup.log and $env:tmp\Installer-ConfigFileManager.log
Set-Location $env:tmp
$MyPath2 = (Get-Location).Path
Set-Location $MyPath2
if ( (Get-Location).Path -eq $MyPath2 )
{
	if ( $res = Get-ChildItem -Path .\* -Include Setup.log,Installer-ConfigFileManager.log)
	{
		Set-Location $MyPath
		Write-Output "INSTALL LOGS FILES FOUND:" >> PFC.txt
		for ($i = 0 ; $i -ne $res.Length ; $i++)
		{
			Write-Output ($res[$i] -as [string]) >> PFC.txt
			Copy-Item ($res[$i] -as [string]) $MyPath
		}
	}
	else
	{
		Set-Location $MyPath
		Write-Output "INSTALL LOGS FILES FOUND: niether Setup.log or Installer-ConfigFileManager.log were found in the Windows \Temp folder : $MyPath2" >> PFC.txt
	}

}
else
{
	Set-Location $MyPath
	Write-Output "FOLDER NOT FOUND : $MyPath2" >> PFC.txt
}


#Checking if DB collect has been requested
if ( $DBcollect -eq "y" -or $DBcollect -eq "Y"  )
{
	Write-Output "DB collected" >> PFC.txt

	# SQL DB collect
	# osql DB backup in order to work with both SQLExpress and SQL Server
	# note: ` escape character is necessary to make osql PowerShell V2.0 compatible
	# note 2: when multiple SQL instannce, need to specify the Portal SQL instance (here INSTANCE1)
	# backed up databases are stored in the default /Backup folder (see SSMS configuration)
	# osql `-E `-S .\INSTANCE1 `-Q"BACKUP DATABASE EVaultWeb TO DISK = 'EVaultWeb.bin'"
	#	Processed 456 pages for database 'EVaultWeb', file 'EVaultWeb' on file 1.
	#	Processed 3 pages for database 'EVaultWeb', file 'EVaultWeb_log' on file 1.
	#	BACKUP DATABASE successfully processed 459 pages in 0.120 seconds (29.874 MB/sec).
	# note 3: the path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names" is where you find the different instance names installed on this server
	# and "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\EVault\InfoStage\Portal\Notification" where Portal SQL server config file is on the SQL back end

#	cd HKLM:
#	cd \SOFTWARE\Wow6432Node\EVault\InfoStage\
#	PS HKLM:\SOFTWARE\Wow6432Node\EVault\InfoStage> $Portal
#
#
#	Hive: HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\EVault\InfoStage
#
#
#	Name                           Property
#	---- --------
#   [...]
#	NotificationDir      : C:\inetpub\Portal Services Website\Notification

	$A = Get-Item -Path HKLM:\SOFTWARE\Wow6432Node\EVault\InfoStage\Portal\
<#	PS C:\Users\Administrator> $A.GetValue("NotificationDir")
	C:\inetpub\Portal Services Website\Notification
	#>
	$NotificationWebConfig = $A.GetValue("NotificationDir")

<#	extract of interest from NotificationWebConfig "Web.config" file
	>>
	<add key="UserManagement.Sql.Connection" value="Data Source=CLONE1\INSTANCE1;Database=UserManagement;User ID=sa;Password=3Vlt1nc" />
	#>

	$ConsumeReturnValue = Get-Content $NotificationWebConfig\Web.config | Where-Object { $_ -match "Data Source=.*\\(?<InstanceName>.*)';Database='UserManagement'" }


#	'^Full Computer.* (?[^.]+)\.   $matches.computer brucepay64 from "Windows_PowerShell_in_Action_Third_Edit_v11_MEAP.pdf"

	$Instance = $Matches.InstanceName

<#	Result of "$Instance = $Matches.InstanceName"
	Name	Type	Value
	Instance	String	INSTANCE1#>


	$ConsumeReturnValue = Invoke-Command -ScriptBlock { osql `-E `-S .\$Instance `-Q"BACKUP DATABASE EVaultWeb TO DISK = 'EVaultWeb.bin'"}
	$ConsumeReturnValue = Invoke-Command -ScriptBlock { osql `-E `-S .\$Instance `-Q"BACKUP DATABASE SiteManagement TO DISK = 'SiteManagement.bin'"}
	$ConsumeReturnValue = Invoke-Command -ScriptBlock { osql `-E `-S .\$Instance `-Q"BACKUP DATABASE UserManagement TO DISK = 'UserManagement.bin'"}
	$ConsumeReturnValue = Invoke-Command -ScriptBlock { osql `-E `-S .\$Instance `-Q"BACKUP DATABASE WebCC TO DISK = 'WebCC.bin'"}
	$ConsumeReturnValue = Invoke-Command -ScriptBlock { osql `-E `-S .\$Instance `-Q"BACKUP DATABASE VaultReporting TO DISK = 'VaultReporting.bin'"}

	# here we look for the folder where the DB is backed up
<#	$A = reg query "HKLM\Software\Microsoft\Microsoft SQL Server"
	$B = $A | Where-Object {$_ -like "*MSSQL*" } | Where-Object {$_ -notlike "*MSSQLServer*"}
	$SQLBackupItems = $B.Replace("HKEY_LOCAL_MACHINE\Software\Microsoft","C:\Program Files") + "\MSSQL\Backup\*.bin"#>


	$SQLBackupItems = Get-SQLBackupDirectoryForInstance -InstanceName $Instance

<#	C:\Program Files\Microsoft SQL Server\MSSQL11.INSTANCE1\MSSQL\Backup#>

	# and then copy the DBs to our collect folder
	Copy-Item -Path $SQLBackupItems -Destination $MyPath -Recurse -Container: $false

	Get-ChildItem $SQLBackupItems | Select-Object -Property FullName | Out-File PFC.txt -Append -NoClobber

}
else
{
	Write-Output '=== No Data Base collected according to user choice ===' >> PFC.txt
}

$SQLERRORLOG = Get-SQLErrorLogPathForInstance -InstanceName $Instance

Write-Output "Collecting ERRORLOG" >> PFC.txt

# Copies ERRORLOG to our collection folder
Copy-Item -Path $SQLERRORLOG\ERRORLOG -Destination $MyPath -Container: $false

"$SQLERRORLOG\ERRORLOG" | Out-File PFC.txt -Append


# call to the zip function
$FP = $MyPath + "\*.*"
# cannot use  (Get-ChildItem $FP).FullName as parenthetical explicit is not supported in PowerShell v 2.0
Get-ChildItem $FP | Select-Object -Property FullName | Out-File "C:\List_of_files_to_zip.txt"
("$MyPath" + "\hosts") | Add-Content "C:\List_of_files_to_zip.txt"
$ConsumeReturnValue  = Get-ChildItem (Get-Content "C:\List_of_files_to_zip.txt") | Set-7zaPswd
Remove-Item "C:\List_of_files_to_zip.txt" -Force

# now deleting all files except the zip file
Set-Location $MyPath

# making sure "$MyPath" is of type "*evaultsupport*" before deleting it
if("$MyPath" -like "*evaultsupport*"){
# Gets the "*evaultsupport*" and all its content (-Recurse) and deletes it forcibly (without asking user's authorization)
Get-Item $MyPath | Remove-Item -Recurse -Force
}

#return to the execution folder
Pop-Location

# re-enable powershell error and warning messages
$ErrorActionPreference = "Continue"

# End of Script