//===================================================TTPs YARA Ruleset================================================
//NOTE: This ruleset will be updated with modifications to existing rules and addition of new rules as the 100 Days of YARA challenge progresses
//IMPORTANT: Please copy paste the entire ruleset in order to use the rules from Day4 onwards...

private rule TTP_PowerShell_execution
  {strings:
    $pwrshll = "powershell.exe" ascii wide 
    $pwrshllparam1 = "system.net.webclient" ascii wide
    $pwrshllparam2 = "-exec bypass" ascii wide
    $pwrshllparam3 = "-w hidden -nop" ascii wide

  condition:
    $pwrshll and any of ($pwrshllparam*)}

private rule TTP_VBS_Script_embedded
{strings:
    $vbsexec = "<SCRIPT language=\"VBScript\">" ascii wide fullword 
    
  condition:
    $vbsexec}

private rule TTP_WScript_Shell_execution
{strings:
    $wscript = "createobject(\"WScript.Shell\")" ascii wide
    
  condition:
    $wscript}

private rule TTP_Base64_encoding_usage
{strings:
    $base64 = "base64" nocase
    
  condition:
    $base64}

//import "time"
private rule TTP_Tampered_Time_Stamp {
    meta:
        author = "RustyNoob619"
        description = "Detects PE files that have time stamps from the future"
    condition:
        pe.timestamp > time.now()
}

private rule TTP_Embedded_PE_Base64
{
  meta:
    author = "RustyNoob619$"
    description = "Detects Windows PE fiels embedded in other files as Base64 encoded payloads"
    example = "8693e1c6995ca06b43d44e11495dc24d809579fe8c3c3896e972e2292e4c7abd"
    
  strings:
    $base64pe1 = "TVq" //Base64 for MZ
    $base64pe2 = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGU" // Base64 for This program cannot be run in DOS mode.
    $base64pe3 = "BQRQ" //Base64 for PE

  condition:
    all of them 
    and @base64pe3 > @base64pe2
    and @base64pe2 > @base64pe1
}

private rule TTP_Memory_Permissions_Tampering
{
  meta:
    author = "RustyNoob619$"
    description = "Detects tampering of memory protection flags concerning permissions and API calls which is typically used in code injection or unpacking"
    example = "8693e1c6995ca06b43d44e11495dc24d809579fe8c3c3896e972e2292e4c7abd"
    
  strings:
    $protectflg = "0x40" fullword ascii wide
    $protectvalue = "PAGE_READ_WRITE_EXECUTE" ascii wide
    $api = "VirtualProtect" ascii wide

  condition:
    any of ($protect*)
    and $api
}

private rule TTP_AMSI_DLL_Live_Patching
{
  meta:
    author = "RustyNoob619$"
    description1 = "Detects paching the ASMI interface to bypass the security features of the Windows OS. TTP is based on sus API calls & parameters"
    description2 = "The AmsiScanBuffer() function is key component of AMSI on Windows which allows applications to submit data to be scanned by installed AV software"
    example = "8693e1c6995ca06b43d44e11495dc24d809579fe8c3c3896e972e2292e4c7abd"
    reference = "https://isc.sans.edu/diary/Live+Patching+DLLs+with+Python/31218"
    credit = "Xavier Mertens @xme for explaining the internal workings of the TTP"
    
  strings:
    $amsifunc = "AmsiScanBuffer" ascii wide
    $apis1 = "GetProcAddress" ascii wide
    $apis2 = "LoadLibraryA" ascii wide
    $apis3 = "RtlMoveMemory" ascii wide

  condition:
    TTP_Memory_Permissions_Tampering
    and $amsifunc
    and 2 of ($api*)
}

private rule TTP_ETW_DLL_Live_Patching
{
  meta:
    author = "RustyNoob619$"
    description1 = "Detects paching the ASMI interface to bypass the security features of the Windows OS. TTP is based on sus API calls & parameters"
    description2 = "The EtwEventWrite() function in Windows is a core component of the ETW framework. It allows applications to log events that can be captured and analysed for debugging, performance monitoring & security auditing."
    example = "8693e1c6995ca06b43d44e11495dc24d809579fe8c3c3896e972e2292e4c7abd"
    reference = "https://isc.sans.edu/diary/Live+Patching+DLLs+with+Python/31218"
    credit = "Xavier Mertens @xme for the explaining internal workings of the TTP"
    
  strings:
    $etwfunc = "EtwEventWrite" ascii wide
    $apis1 = "GetProcAddress" ascii wide
    $apis2 = "LoadLibraryA" ascii wide
    $apis3 = "RtlMoveMemory" ascii wide

  condition:
    TTP_Memory_Permissions_Tampering
    and $etwfunc
    and 2 of ($api*)
}

private rule TTP_DLL_Enum_Security_Products
{
  meta:
    author = "Rustynoob619"
    description = "Detects Windows executables that attempt to enumerate security product file names for defense evasion"
    example_filehash = "78f86c3581ae893e17873e857aff0f0a82dcaed192ad82cd40ad269372366590"
  
  strings:
  
    $secprdct1 = "ZhuDongFangYu.exe" nocase ascii wide fullword
    $secprdct2 = "360sd.exe" nocase ascii wide fullword
    $secprdct3 = "kxetray.exe" nocase ascii wide fullword
    $secprdct4 = "KSafeTray.exe" nocase ascii wide fullword
    $secprdct5 = "QQPCRTP.exe" nocase ascii wide fullword
    $secprdct6 = "HipsDaemon.exe" nocase ascii wide fullword
    $secprdct7 = "BaiduSd.exe" nocase ascii wide fullword
    $secprdct8 = "baiduSafeTray.exe" nocase ascii wide fullword
    $secprdct9 = "KvMonXP.exe" nocase ascii wide fullword
    $secprdct10 = "RavMonD.exe" nocase ascii wide fullword
    $secprdct11 = "QUHLPSVC.EXE" nocase ascii wide fullword
    $secprdct12 = "QuickHeal" nocase ascii wide fullword
    $secprdct13 = "mssecess.exe" nocase ascii wide fullword
    $secprdct14 = "cfp.exe" nocase ascii wide fullword
    $secprdct15 = "SPIDer.exe" nocase ascii wide fullword
    $secprdct16 = "DR.WEB" nocase ascii wide fullword
    $secprdct17 = "acs.exe" nocase ascii wide fullword
    $secprdct18 = "Outpost" nocase ascii wide fullword
    $secprdct19 = "V3Svc.exe" nocase ascii wide fullword
    $secprdct20 = "AYAgent.aye" nocase ascii wide fullword
    $secprdct21 = "avgwdsvc.exe" nocase ascii wide fullword
    $secprdct22 = "AVG" nocase ascii wide fullword
    $secprdct23 = "f-secure.exe" nocase ascii wide fullword
    $secprdct24 = "F-Secure" nocase ascii wide fullword
    $secprdct25 = "avp.exe" nocase ascii wide fullword
    $secprdct26 = "Mcshield.exe" nocase ascii wide fullword
    $secprdct27 = "egui.exe" nocase ascii wide fullword
    $secprdct28 = "NOD32" nocase ascii wide fullword
    $secprdct29 = "knsdtray.exe" nocase ascii wide fullword
    $secprdct30 = "TMBMSRV.exe" nocase ascii wide fullword
    $secprdct31 = "avcenter.exe" nocase ascii wide fullword
    $secprdct32 = "ashDisp.exe" nocase ascii wide fullword
    $secprdct33 = "rtvscan.exe" nocase ascii wide fullword
    $secprdct34 = "remupd.exe" nocase ascii wide fullword
    $secprdct35 = "vsserv.exe" nocase ascii wide fullword
    $secprdct36 = "BitDefender" nocase ascii wide fullword
    $secprdct37 = "PSafeSysTray.exe" nocase ascii wide fullword
    $secprdct38 = "ad-watch.exe" nocase ascii wide fullword
    $secprdct39 = "K7TSecurity.exe" nocase ascii wide fullword
    $secprdct40 = "UnThreat.exe" nocase ascii wide fullword
    $secprdct41 = "UnThreat" nocase ascii wide fullword
    $secprdct42 = "HipsTray.exe" nocase ascii wide fullword
    $secprdct43 = "MsMpEng.exe" nocase ascii wide fullword // not in the sample
    $secprdct44 = "360tray.exe" nocase ascii wide fullword
    $secprdct45 = "360Safe.exe" nocase ascii wide fullword
    $secprdct46 = "kscan.exe" nocase ascii wide fullword
    $secprdct47 = "kxescore.exe" nocase ascii wide fullword
    $secprdct48 = "kwsprotect64.exe" nocase ascii wide fullword
    $secprdct49 = "QQRepair.exe" nocase ascii wide fullword
    $secprdct50 = "QQPCTray.exe" nocase ascii wide fullword
    $secprdct51 = "QQPCRealTimeSpeedup.exe" nocase ascii wide fullword
    $secprdct52 = "QQPCPatch.exe" nocase ascii wide fullword
    $secprdct53 = "QMPersonalCenter.exe" nocase ascii wide fullword
    $secprdct54 = "QMDL.exe" nocase ascii wide fullword
    $secprdct55 = "HipsMain.exe" nocase ascii wide fullword
    $secprdct56 = "Comodo" nocase ascii wide fullword
    $secprdct57 = "avpui.exe" nocase ascii wide fullword
    $secprdct58 = "egui.exe" nocase ascii wide fullword
    $secprdct59 = "Ad-watch" nocase ascii wide fullword

    $secprdct60 = "Fiddler" nocase ascii wide fullword
    $secprdct61 = "Wireshark" nocase ascii wide fullword
    $secprdct62 = "Metascan" nocase ascii wide fullword
    $secprdct63 = "TaskExplorer" nocase ascii wide fullword
    $secprdct64 = "Malwarebytes" nocase ascii wide fullword
    $secprdct65 = "TCPEye" nocase ascii wide fullword
    $secprdct66 = "CurrPorts" nocase ascii wide fullword
    $secprdct67 = "ApateDNS" nocase ascii wide fullword

  condition:
    uint16(0) == 0x5a4d
    and any of them
}

private rule File_Format_Script_Python
{
  meta:
    author = "RustyNoob619$"
    description = "Detects Python scripts based on typical functions used in Python"
    
  strings:
    $imprts1 = "import clr" fullword
    $imprts2 = "import base64" fullword
    $imprts3 = "import ctypes" fullword
    $imprts4 = "import platform" fullword
    $imprts5 = "import sys" fullword
    $imprts6 = "import Assembly" fullword
    $imprts7 = "import windll" fullword
    
    $pyfrom = "from"
    $pyprint = "print("
    $pyif = "if"
    $pyfor = "for"
    $pywhile = "while"
    
  condition:
    any of ($imprts*) and any of ($py*)
    
}
//import "elf"
private rule Packer_ELF_UPX
{
  meta:
    author = "RustyNoob619"
    description = "Detects ELF samples that are packed with the UPX packer based on the sections in the file"
    filehash = "e5e475db5076e112f69b61ccb36aaedfbb7cac54a03a4a2b3c6a4a9317af2196"
  
  condition:
    for any section in elf.sections:
    (section.name startswith ".upx")
}

private rule Header_File_HTA
{strings:
    $html= {3c 21 44 4f	43 54 59 50	45 20 68 74	6d 6c 3e 0a}
    
  condition:
    $html at 0}

private rule Header_File_LNK
{strings:
    $lnk = {4C 00 00 00 01 14 02 00}
    
  condition:
    $lnk at 0}

private rule Header_File_VBS
{condition:
    uint32be(0) == 0x64696d20} //dim

private rule APT_RU_UAC0099_attributes
{strings:
    $usragnt = "Ds26GOZNxbTxlJY" ascii wide
    $c2url = "https://newyorktlimes.life/api/values"
    
  condition:
    any of them}

private rule File_Path_C_Users_Public_Docs
{strings:
    $vbspath1 = "C:\\\\Users\\\\Public\\\\Documents\\\\" ascii wide
    $vbspath2 = "C:\\Users\\Public\\Documents\\" ascii wide
    
  condition:
    any of them}

private rule Scheduled_Tasks_ExplorerCoreUpdateTaskMachine
{strings:
    $schtsks = "schtasks.exe /create /TN ExplorerCoreUpdateTaskMachine" ascii wide
    $schtsksparams = "/SC minute /mo 3 /tr"
    
  condition:
    all of them}
