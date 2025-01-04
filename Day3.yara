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
