﻿<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2016 v5.2.123
	 Created on:   	7/26/2016 9:23 PM
	 Created by:   	Thierry Cailleau
	 Organization: 	
	 Filename:     	
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>
#I have installed an a single test VM:
#- UI Portal 7.70
#- Evault Reports 2.74
#- Director Vault 7.11
#- Agent 7.50
#
#All of this on a Server 2012 installed with SQL 2012 SP1
#
#Now, there is a serious advantage with such settings, you are independent of most network dependencies.
#
#All but one, the AMP Proxy Listener IP address as defined in "AmpService.exe.config". This is the only hard-coded IP address that cannot be swapped by a hostname or a fqdn.

# C:\Program Files\EVault Software\Portal Services\AMP Proxy Service\Set-AMPProxyIP.ps1
# Stopping AMPRedirectorService then AMPProxyService service
Get-Service -Name AMPRedirectorService | Stop-Service
Get-Service -Name AMPProxyService | Stop-Service
# Expand each line of "AmpService.exe.config" into an array stored into a variable $AMPProxy
$AMPProxy = Get-Content "C:\Program Files\EVault Software\Portal Services\AMP Proxy Service\AmpService.exe.config"
# Takes line 14 (starting at 0 for an array, i.e. really line 15) of the "AmpService.exe.config"
# Example of line 15:     <add key="Proxy.Agent.Listen.IpAddress" value="192.168.47.127" />
$OldLine = ($AMPProxy)[14]
# Finds everthing before and after 'value="' and capture the one before last result, here the full IP address 192.168.47.127
[string]$IPadd = ($AMPProxy)[14].Split('value="')[-2]
# uses ipconfig lines (filetered to contain keyword IPv4) and get the last entry after ' : '
[string]$IPNow = (ipconfig | findstr IPv4).Split(' : ')[-1]
# replaces old IP by current IP in line 15
[string]$NewLine = ($AMPProxy)[14].Replace("$IPadd", "$IPNow")
# replaces line 15 in "AmpService.exe.config" variable $AMPProxy then write the content of this to AmpService.exe.config (-Force is to replace the whole file's content)
$AMPProxy.Replace("$OldLine", "$NewLine") | Out-File -FilePath "C:\Program Files\EVault Software\Portal Services\AMP Proxy Service\AmpService.exe.config" -Force
# Restart AMPProxyService Service first
Get-Service -Name AMPProxyService | Start-Service
# Restart AMPRedirectorService Service second
Get-Service -Name AMPRedirectorService | Start-Service
# tested to work with PS v3, fails with v2