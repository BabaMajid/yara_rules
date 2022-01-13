import "pe"
rule heodo_emotet{
 meta:
Description= "Hedo dll detector that is dropped by emotet"
Author="Majid Jahangeer"
Date="13-01-2021"

strings:

$s1="Netsh interface set interface" nocase ascii
$s2="Control Panel\\Desktop\\ResourceLocale" nocase ascii
$reg1="Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" nocase ascii
$reg2="Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Network" nocase ascii
$reg3="Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Comdlg32" nocase ascii

condition:
(all of ($s*)) and (1 of ($reg*)) or (pe.imports("ole32.dll","OleFlushClipboard") and pe.imports("user32.dll","GetClipboardData") and uint16(0)==0x5A4D)

}
