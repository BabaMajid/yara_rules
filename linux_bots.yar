rule mirai_bot_linux
{
meta:
	description = " Mirai bot rule for detecting ELF files on linux OS"
	author = "Majid Jahangeer"
	date = "23-12-2021"

strings:
	$s2 = "gethostbyname" ascii
	$s3 = "/etc/resolv.conf"
	$s5 = "HuaweiHomeGateway"

condition:
	 2 of ($s*)and (uint32(1)==0x01464C45 and filesize <200KB)

}

rule mirai_executable
{
meta:
	description = " Mirai bot rule for detecting ELF files on linux OS"
	author = "Majid Jahangeer"
	date = "11-01-2022"

strings:
	$s1 ={67 72 65 65 6b 2e 48 65 6c 69 6f 73}

condition:

$s1 and uint32(0)==0x464c457f

}

rule gafgyt_linux
{
meta:
	description = " Gafgyt rule for detecting ELF files on linux OS"
	author = "Majid Jahangeer"
	date = "11-01-2022"

strings:
	$s1={2f 65 74 63 2f 63 6f 6e 66 69 67 2f 68 6f 73 74 73}

	$s2={2f 65 74 63 2f 72 65 73 6f 6c 76 2e 63 6f 6e 66}
	$text1="XENIX semaphores" nocase ascii
condition:
1 of ($s*) and (all of ($text*))

}
