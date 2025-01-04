// Please Reference the ruleset of Day3 :)

rule HTA_APT_RU_UAC0099_strings
{ 
  meta:
    author = "RustyNoob619"
    description = "Detects HTA file used as the first stage in a campaign against Ukraine Gov Entities between NOV & DEC 2024"
    source = "https://cert.gov.ua/article/6281681"
    filehash = "88b64a3eb0dc38e3f8288b977b1cd67af7d4ba959297ac48ef5f06bec3e77560"

  condition:
    Header_File_HTA
    and (APT_RU_UAC0099_attributes
    or 
    (TTP_VBS_Script_embedded
    and TTP_WScript_Shell_execution
    and TTP_Base64_encoding_usage
    and TTP_PowerShell_execution
    and File_Path_C_Users_Public_Docs
    and Scheduled_Tasks_ExplorerCoreUpdateTaskMachine))
    and filesize < 25KB
    }

rule LNK_APT_RU_UAC0099_strings
{
  meta:
    author = "RustyNoob619"
    description = "Detects LNK file used as the first stage in a campaign against Ukraine Gov Entities between NOV & DEC 2024"
    source = "https://cert.gov.ua/article/6281681"
    filehash = "cd2eb07158cbc56db4979dd0ef8e73b5c06929d8eeb5af717210b2d53df94fbf"

  condition:
    Header_File_LNK
    and (APT_RU_UAC0099_attributes
    or 
    (TTP_Base64_encoding_usage
    and TTP_PowerShell_execution
    and File_Path_C_Users_Public_Docs
    and Scheduled_Tasks_ExplorerCoreUpdateTaskMachine))
    and filesize < 25KB
    }

rule VBS_APT_RU_UAC0099_strings
{ 
  meta:
    author = "RustyNoob619"
    description = "Detects VBS script used as the first stage in a campaign against Ukraine Gov Entities between NOV & DEC 2024"
    source = "https://cert.gov.ua/article/6281681"
    filehash1 = "0f05990ef107e49b59bc8d736cdd9535e514efb18e5246fb2b7dc2b7d3305784"
    filehash2 = "71aac82441162ed0a61d30a75d057402adcce4e1a81e61941a41a0385c7e7b0b"

  condition:
    Header_File_VBS 
    and (APT_RU_UAC0099_attributes
    or 
    (TTP_WScript_Shell_execution
    and TTP_PowerShell_execution
    and File_Path_C_Users_Public_Docs))
    and filesize < 5KB
    }
