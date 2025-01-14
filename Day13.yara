import "pe"

rule EXE_Backdoor_PLAYFULGHOST
{
  meta:
    author = "Rustynoob619"
    description = "Detects Windows executables that drop QAssist rootkit as part of the PLAYFULGHOST malware infection"
    reference = "https://www.googlecloudcommunity.com/gc/Community-Blog/Finding-Malware-Unveiling-PLAYFULGHOST-with-Google-Security/ba-p/850676"
    filehash = "4800add84a0ace4482dbe4ac41e69dc49f87ddaba3d7571235f9d0784c01b7ae"
  
  strings:
    $str1 = "Sainbox COM Support" fullword
    $str2 = "Sainbox COM Services (DCOM)" fullword
    $str3 = "%SystemRoot%\\System32\\" fullword
    $str4 = "MS Shell Dlg" fullword 

  condition:
    pe.language(0x0004) //Chinese Simplified Language
    and pe.imphash() == "de6942886ea1706308de6a5dc748b51c"
    and 3 of them 
    and filesize < 5MB
}

rule DLL_Backdoor_PLAYFULGHOST
{
  meta:
    author = "Rustynoob619"
    description = "Detects Windows DLLs that load the PLAYFULGHOST malware as the final payload"
    reference = "https://www.googlecloudcommunity.com/gc/Community-Blog/Finding-Malware-Unveiling-PLAYFULGHOST-with-Google-Security/ba-p/850676"
    filehash = "78f86c3581ae893e17873e857aff0f0a82dcaed192ad82cd40ad269372366590"
  
  strings:
    $str1 = "%s\\shell\\open\\command" wide fullword
    $str2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide fullword
    $tencent = "Software\\Tencent\\Plugin\\VAS" wide fullword
    
    $secprdct1 = "ZhuDongFangYu.exe" wide fullword
    $secprdct2 = "360sd.exe" wide fullword
    $secprdct3 = "kxetray.exe" wide fullword
    $secprdct4 = "KSafeTray.exe" wide fullword
    $secprdct5 = "QQPCRTP.exe" wide fullword
    $secprdct6 = "HipsDaemon.exe" wide fullword
    $secprdct7 = "BaiduSd.exe" wide fullword
    $secprdct8 = "baiduSafeTray.exe" wide fullword
    $secprdct9 = "KvMonXP.exe" wide fullword
    $secprdct10 = "RavMonD.exe" wide fullword
    $secprdct11 = "QUHLPSVC.EXE" wide fullword
    $secprdct12 = "QuickHeal" wide fullword
    $secprdct13 = "mssecess.exe" wide fullword
    $secprdct14 = "cfp.exe" wide fullword
    $secprdct15 = "SPIDer.exe" wide fullword
    $secprdct16 = "DR.WEB" wide fullword
    $secprdct17 = "acs.exe" wide fullword
    $secprdct18 = "Outpost" wide fullword
    $secprdct19 = "V3Svc.exe" wide fullword
    $secprdct20 = "AYAgent.aye" wide fullword
    $secprdct21 = "avgwdsvc.exe" wide fullword
    $secprdct22 = "AVG" wide fullword
    $secprdct23 = "f-secure.exe" wide fullword
    $secprdct24 = "F-Secure" wide fullword
    $secprdct25 = "avp.exe" wide fullword
    $secprdct26 = "Mcshield.exe" wide fullword
    $secprdct27 = "egui.exe" wide fullword
    $secprdct28 = "NOD32" wide fullword
    $secprdct29 = "knsdtray.exe" wide fullword
    $secprdct30 = "TMBMSRV.exe" wide fullword
    $secprdct31 = "avcenter.exe" wide fullword
    $secprdct32 = "ashDisp.exe" wide fullword
    $secprdct33 = "rtvscan.exe" wide fullword
    $secprdct34 = "remupd.exe" wide fullword
    $secprdct35 = "vsserv.exe" wide fullword
    $secprdct36 = "BitDefender" wide fullword
    $secprdct37 = "PSafeSysTray.exe" wide fullword
    $secprdct38 = "ad-watch.exe" wide fullword
    $secprdct39 = "K7TSecurity.exe" wide fullword
    $secprdct40 = "UnThreat.exe" wide fullword
    $secprdct41 = "UnThreat" wide fullword
    $secprdct42 = "HipsTray.exe" wide fullword
    $secprdct43 = "MsMpEng.exe" wide fullword
    $secprdct44 = "360tray.exe" wide fullword

  condition:
    $tencent
    and any of ($str*)
    and 30 of ($secprdct*)
    and filesize < 250KB
}
