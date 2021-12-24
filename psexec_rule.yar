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
      $s8 = "Run the remote process in the System account." fullword ascii

   condition:
  filesize < 2000KB and
      1 of ($x*) and 2 of ($s*)
}

