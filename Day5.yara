// Added the below to Day3 ruelset to centralise TTPs in one place
rule TTP_Embedded_PE_Base64
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

rule TTP_Memory_Permissions_Tampering
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

rule File_Format_Script_Python
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

// Added the above to Day3 ruelset to centralise TTPs in one place
