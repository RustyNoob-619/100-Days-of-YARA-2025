rule JS_APT_DPRK_ContagiousInterview_strings
{
  meta:
    author = "RustyNoob619"
    description = "Detects DPRK cluster known as  Contagious Interview JavaScript samples based on visible human-readable strings"
    credit = "Dmitry Bestuzhev @dimitribest for sharing the malware samples and providing an overview of the malware capabilities"
    source = "https://x.com/dimitribest/status/1872743641166606737"
    filehash1 = "ab754242fe28fa282a9169e47c3e12752fa444c22945cd220c657bcab561b983"
    filehash2 = "d62614d8c7f2eb68202d0d73a84e621008cfbe8d7e652952ad26206620aea76d"
    
  strings:
    $port = "'5346'" fullword
    $brwsr1 = "Googl" 
    $brwsr2 = "Brave" fullword
    $brwsr3 = "opera" fullword
    $file1 = "filen" 
    $file2 = "FileS" 
    $file3 = "_file"
    $str1 = "Local" fullword
    $str2 = "size" fullword
    $str3 = "apply" fullword
    $str4 = "acces"
    $str5 = "sync" 
    $str6 = "child_proc" 
    $str7 = "exec" fullword
    $str8 = "hostname" fullword
    
  condition:
    $port
    and 11 of them
    and filesize < 100KB
}
