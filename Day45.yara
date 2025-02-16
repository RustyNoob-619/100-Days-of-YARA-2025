rule JS_APT_DPRK_ContagiousInterview_strings
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

//Cluster of files matching str3
//1f4951fdf57a81d0e8adc164a9e90394782b9bc9
//4483561a49791a7cd684258e9f1623fe7dfba772
//d03b70ea52e68cb60d293498d9c886858d641985
//b82f1e7bb642fec7d304c54670857689b33796e2
//8d66ee7abb7e3c8aae37bf3b0e33544f19c9c684
//167d72bab21c0b6c2e2259ebae15fe370adb6da7
//1ad9a206b45a1bbd30461007dd2c79dac918551c
//01ad32027b6b4815b6845191059429bb76f39967
//372fc8c234dca2457e3fbbfb5e9a102dce5ec5a7
//f990880b4199c7f1b5038b3f63bf0f79168f447c
//32e182f04e0ec3dec094775490ab76ff1dbdccfc
//f372ac1b0cf4721af8abb968dfbfb7b79fc097ec
//df7ffd20940c227dac2b37a2646e819cad5a52dd
//5f796c9d00c14daa52ad208f28a1e750f6ef0b72
//a53ec4c13994695e9dde15a003dabf50f6eb9fe3
//0dc090c9afb2ed1d098297b0e1ef2a7b2536ee99
//3d85aed17a6a9337536cedafc0f966040ea94770
//d415faa9d8e2d44fb9e5e1274a3bb5926da0c2a0
//c8993ef0064acdb3a90a1470f3f4dc2714822a15

