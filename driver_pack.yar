import "pe"
rule driver_pack_malware
{
meta: 
	description = "Driver Pack Malware- Crypto Miner"
	Author = "Majid Jahangeer"
strings :
	$lolbin = "%s\\System32\\mshta.exe" fullword wide
	$str1="Tools\\run.hta" fullword wide
	$str2="ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION" nocase fullword wide
	$str3="/DELETE /YES" fullword wide
condition:	
(uint16(0)==0x5A4D) and $lolbin and 1 of ($str*) and (pe.imports("shell32.dll","ShellExecuteW") or pe.imports("kernel32.dll","SetCurrentDirectoryW"))

}
