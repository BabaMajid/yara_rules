rule mirai_bot_linux
{
meta:
	description = " Mirai bot rule for detecting ELF files on linux OS"
	author = "Majid Jahangeer"
	date = "23-12-2021"

strings:
	$s2 = "gethostbyname" ascii
	$s3 = "/etc/resolv.conf"
	$s6 = "chmod +x" ascii
	$s5 = "HuaweiHomeGateway"

condition:
	 2 of ($s*)and (uint32(1)==0x01464C45 and filesize <200KB)

}
