rule Exploit_URL_CVE20250411_strings_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects the .url file used to drop second stage (Smokeloader) by exploiting a Zero-Day CVE-2025-0411 to bypass MoTW in a targeted Ukrainian campaign"
    source = "https://www.trendmicro.com/en_us/research/25/a/cve-2025-0411-ukrainian-organizations-targeted.html"
    filehash = "2e33c2010f95cbda8bf0817f1b5c69b51c860c536064182b67261f695f54e1d5"
    
  strings:
    $header = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d}
    $str1 = "invoice.zip"
    $str2 = ".dll"
    $str3 = "Prop3=19,9" ascii fullword
    
  condition:
    $header at 0 
    and all of them
    and filesize < 100KB
}


