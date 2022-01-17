import "pe"
rule kms_cracker 
{
meta:
description="KMS Crack detector rule that identify executable that loads main dll file"
author="Majid Jahangeer"
Date="17-01-2022"
Email="mianmajid432@gmail.com"
hash1="0C8CE6392B838D1CE87E2DAA36837723DBC5EF08C4FBBE388F061A0D9FC9E6CA"

strings:
 $s1 = "KMS-QADhook.dll" fullword wide
$s2="DebugActiveProcessStop"


condition:
all of ($s*) and uint16(0)==0x5A4D and pe.imports("kernel32.dll","DebugActiveProcessStop")
}
