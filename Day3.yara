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
