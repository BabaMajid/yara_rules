import "pe"

rule ABADDON_detection
{
meta:
	author = "Majid Jahangeer"
	description = "Rule for detecting Abaddon malware that targets POS system"
	
	

strings:
	$str1 = { 31 DB 89 D8 69 C0 [4] 3D [4] 76 ?? B8 [4] EB ?? 05 [4] 8B 55 }
	$str2 = { 80 FA ?? 75 ?? 88 94 0E [4] 41 EB ?? EB ?? 80 BE [5] 75 ?? 80 FA }

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and (($str1 in (820..7500) and $str2 in (0..6600)))
 }
