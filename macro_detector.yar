rule macro_detector{

meta:
description="Macro Detector in  Office Document"
Author="Majid Jahangeer"


strings:
$s1="rundll32.exe" nocase ascii
$s2="powershell.exe" nocase ascii
$s3="cmd.exe" nocase ascii
$s4="wmi.exe" nocase ascii
$s5="wmic.exe" nocase ascii
$s6= "certutil.exe"
$p1="system32" nocase
$p2="syswow64" nocase
$h1 = {D0 CF 11 E0}
$h2 = {50 4B 03 04}

condition:
1 of ($s*) and 1 of ($p*) and ($h1 in (0..4) or $h2 in (0..4))

}
