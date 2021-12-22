rule yara_sample_PsExec {
   meta:
      description = "Rule to detect PSexec tool"
      author = "Majid Jahangeer"
      date = "2021-12-22"
   strings:
      $x1 = "PSEXEC" fullword wide
      $x2 = "Execute processes remotely" fullword wide
      $s1 = "\\psexec.pdb" fullword ascii
      $s2 = "\\psexesvc.pdb" fullword ascii
      $s3 = "\\admin$\\PSEXEC" fullword wide
      $s4 = "sNtdll.dll" fullword wide
      $s5 = "tnetapi32.dll" fullword wide
      $s6 = "Fmsvcrt.dll" fullword wide
      $s7 = "Emsvcrt.dll" fullword wide
      $s8 = "Run the remote process in the System account." fullword ascii
      $s9 = "PsExec will execute the command on each of the computers listed" fullword ascii

   condition:
  filesize < 2000KB and
      1 of ($x*) and 3 of ($s*)
}

