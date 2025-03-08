
rule Actor_UNK_CraftyCamel_MAL_Loader_Sosano_strings_MAR25
{
  meta:
    author = "RustyNoob619"
    description = "Detects a Windows executable responsible for loading Sosano backdoor that is used by UNK_CraftyCamel based on strings"
    source = "https://www.proofpoint.com/us/blog/threat-insight/call-it-what-you-want-threat-actor-delivers-highly-targeted-multistage-polyglot"
    filehash = "0c2ba2d13d1c0f3995fc5f6c59962cee2eb41eb7bdbba4f6b45cba315fd56327"
    
  strings:
    $key1 = "1234567890abcdef" ascii fullword
    $key2 = "abcdef1234567890" ascii fullword
    $key3 = "0fedcba987654321" ascii fullword

    $pdb = "D:\\gozaresh10" ascii fullword
    $img = "//sosano.jpg" ascii fullword

    //Injection Import Functions
    $func1 = "WriteProcessMemory" ascii fullword
    $func2 = "LoadLibraryA" ascii fullword
    $func3 = "GetProcAddress" ascii fullword
    $func4 = "VirtualAllocEx" ascii fullword
    $func5 = "ReadProcessMemory" ascii fullword
    $func6 = "CreateRemoteThread" ascii fullword
    $func7 = "VirtualFreeEx" ascii fullword
    $func8 = "GetCurrentProcess" ascii fullword

    $str1 = "aa.txt" ascii fullword
    $str2 = "bb.txt" ascii fullword
    $str3 = "root =" ascii fullword

  condition:
    uint16(0) == 0x5a4d
    and ($pdb or $img)
    or ((any of ($key*) and 5 of ($func*) and any of ($str*)))
    and filesize < 500KB
}
